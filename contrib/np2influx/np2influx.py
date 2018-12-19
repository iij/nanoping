#!/usr/bin/env python3.6
# -*- coding:utf-8 -*-
"""
The MIT License
Copyright (c) 2018 Yojiro UO
"""

import argparse
import configparser
from datetime import datetime
import io
import logging
import os
import shlex
import signal
import subprocess
import sys
import time
import numpy as np
import pandas as pd

from influxdb import InfluxDBClient, DataFrameClient


class NPlog(object):
    def __init__(self, filename, duration=5, max_lines=1000, timeout=5, tail=False):
        self.filename = filename
        self.duration = duration
        self.max_lines = max_lines
        self.go_to_tail_first = tail
        self.count = 0
        self.max_retry = 5
        self.timeout = timeout
        self.curloc = 0
        self.iof = None
        self.f = None
        self.origin_c = None
        self.origin_s = None
        self.offset_c = None
        self.offset_s = None
        self.last_df = None

        while(True):
            try:
                self.f = open(self.filename, "r")
            except:
                self.max_retry -= 1
                logger.info('open failed: {}, retry..'.format(self.filename))
                time.sleep(1)
            else:
                logger.debug('log file opened: {}'.format(self.filename))

            if self.f:
                break
            if self.max_retry < 0:
                break

        if self.f is None:
            raise IOError

        if self.go_to_tail_first:
            # move to tail of the file
            self.f.seek(0, 2)
            self.curloc = self.f.tell()

    def _next(self):
        stime = time.time()
        self.f.seek(self.curloc, 0)
        if self.iof:
            self.iof.close()
        self.iof = io.StringIO()
        
        lines = 0
        trycnt = 0
        while True:
            line = self.f.readline()
            if not line:
                trycnt += 1
                if self.timeout:
                    if (trycnt >= self.timeout):
                        break
                time.sleep(1)
                continue
            lines += 1
            trycnt = 0
            self.iof.write(line.strip())
            self.iof.write('\n')

            if lines > self.max_lines:
                break
            if (time.time() - stime) > self.duration:
                break

        curloc = self.f.tell()
        if curloc == self.curloc:
            raise EOFError

        self.curloc = curloc
        self.count += 1

    def _csv2df(self, buf):
        header = ['seq','stat','t0','t1','t2','t3','t3-t0','t2-t1','rtt','delta_t','num_txs']
        target = ['seq','stat','t0','t1','t2','t3','rtt']
        if self.count == 1: # special case, need to header line handling
            r = pd.read_csv(io.StringIO(buf), encoding='UTF-8', header=None, skiprows=2, index_col=0, 
                    dtype=object, names=header, usecols=target)
        else: # no header line
            r = pd.read_csv(io.StringIO(buf), encoding='UTF-8', header=None, index_col=0, 
                    dtype=object, names=header, usecols=target)

        # filter out error lines
        r = r[r.stat=='ok']
        del r['stat']

        if self.count == 1: # record time offset to calculate relative time
            r = r.reset_index(drop=True)
            self.origin_c = r.t0[0]
            self.origin_s = r.t1[0]
            self.offset_c = np.uint64(r.t0[0].replace('.',''))
            self.offset_s = np.uint64(r.t1[0].replace('.',''))
        r = self._convert_time(r)
        r = self._calc_jitter(r)
        return r

    def _convert_time(self, df):
        # relative time (unit=ns)
        df['t0r'] = df['t0'].apply(lambda x: np.uint64(x.replace('.','')) - self.offset_c).astype(np.uint64)
        df['t3r'] = df['t3'].apply(lambda x: np.uint64(x.replace('.','')) - self.offset_c).astype(np.uint64)
        df['t1r'] = df['t1'].apply(lambda x: np.uint64(x.replace('.','')) - self.offset_s).astype(np.uint64)
        df['t2r'] = df['t2'].apply(lambda x: np.uint64(x.replace('.','')) - self.offset_s).astype(np.uint64)
        # change unit to ns
        df['rtt'] = df['rtt'].apply(lambda x: np.uint64(x.replace('.',''))).astype(np.uint64)
        # add timestamp
        df['time'] = pd.to_datetime(df['t0'].apply(lambda x: np.uint64(x.replace('.',''))).astype(np.uint64), unit='ns')
        return df

    def _calc_jitter(self, df):
        if self.last_df is not None:
            temp_df = pd.concat([self.last_df[-1:], df], sort=True)
        else:
            temp_df = df
        # jitter
        r_t0 = temp_df['t0r'].diff(periods=1)
        r_t1 = temp_df['t1r'].diff(periods=1)
        r_t2 = temp_df['t2r'].diff(periods=1)
        r_t3 = temp_df['t3r'].diff(periods=1)
        jc = (r_t0 - r_t1).dropna().rename('jitter_c').astype(np.int64)
        js = (r_t2 - r_t3).dropna().rename('jitter_s').astype(np.int64)
        df = pd.concat([df, jc], axis=1)
        df = pd.concat([df, js], axis=1)
        # if lack of data in jc and/or js, the dtype will automatically change to float.
        # prevent unexpected type change, add some workaround here...
        
        df.jitter_c.fillna(jc.mean(), inplace=True)
        df.jitter_s.fillna(js.mean(), inplace=True)
        df = df.assign(jitter_c = df.jitter_c.astype(np.int64))
        df = df.assign(jitter_s = df.jitter_s.astype(np.int64))
        del temp_df
        return df

    def next_df(self):
        self._next()
        buf = self.iof.getvalue()
        self.iof.close() 
        df = self._csv2df(buf)
        #del df['t0']
        del df['t0']
        del df['t1']
        del df['t2']
        del df['t3']
        self.last_df = df
        return df

class tsdb(object):
    def __init__(self, dbname, host='localhost', port=8086, user='root', password='root'):
        self.host = host
        self.port = port
        self.user = user
        self.password = password
        self.dbname = dbname
        self.client = None
        self.protocol = 'json' 

    def _connect(self):
        if self.client is None:
            self.client = DataFrameClient(host=self.host, port=self.port, username=self.user,
                    password=self.password, database=self.dbname)
            #self.client.switch_database(self.dbname)

    def _disconnect(self):
        if self.cleint is not None:
            self.client.close()
            self.client = None

    def _reconnet(self):
        self._disconnect()
        self._connect()

    def create_db(self):
        self._connect()
        dbs = self.client.get_list_database()
        for e in dbs:
            if self.dbname in e.values():
                logger.debug("Database {} is already exist.".format(self.dbname))
                return

        logger.info("Creating database:{}".format(self.dbname))
        self.client.create_database(self.dbname)
        #self._set_retantion_policy()

    def _set_retantion_policy(self):
        self._connect()
        self.client.create_retention_policy(name = 'raw', duration='12h', replication=1, default=True)
        self.client.create_retention_policy(name = 'cooked', duration='52w', replication=1, default=False)

    def check_db(self):
        self._connect()
        db = self.client.get_list_database()
        ms = self.client.get_list_measurements()
        rp = self.client.get_list_retention_policies(self.dbname)
        user = self.client.get_list_users()

        print('db: {}, measurements: {}'.format(db, ms))
        print('retention policy: {}'.format(rp))
        print('users: {}'.format(user))

    def insert(self, df, measurement, tags=None):
        self._connect()
        try:
            result = self.client.write_points(df, measurement, tags=tags, time_precision='n', protocol=self.protocol)
        except:
            logger.info('influxdb write error')
            result = False
        return result

    def query(self, sql):
        self._connect()
        result = self.client.query(sql)
        return result

def handler(signum, frame):
    # something to do during exiting...
    sys.exit(0)

def pd_param():
    # set pandas display parametors
    pd.set_option('display.max_rows', 100)
    pd.set_option('display.max_colwidth', 120)
    pd.set_option('display.width', 120)
    pd.set_option('max_colwidth', 32)
    pd.set_option('precision',4)

def config_parse_args(configfile=None):
    """ Command line arguments and configuration file setting """
    parser = argparse.ArgumentParser(
        description='nanoping log importer to InfluxDB')
    parser.add_argument('--config', type=str, required=True,
                        help='configuration file')
    parser.add_argument('--interface', type=str, required=True,
                        help='interface name')
    parser.add_argument('--log', type=str, required=False, 
                        help='nanoping logfile location')
    parser.add_argument('--db', type=str, required=False,
                        help='database name of InfluxDB')
    parser.add_argument('--debug', action='store_true', 
                        help='turn on debug output')
    parser.add_argument('--dry', action='store_true', 
                        help='dry run mode')

    args =  parser.parse_args()
    config = configparser.ConfigParser()
    config.read(args.config)

    # override by command line option
    if args.db is not None:
        config['influxdb']['db'] = args.db
    return args, config

def setup_logger():
    """logging setting"""
    logger = logging.getLogger(__name__)
    handler = logging.StreamHandler()
    if args.debug:
        handler.setLevel(logging.DEBUG)
        logger.setLevel(logging.DEBUG)
    else:
        handler.setLevel(logging.INFO)
        logger.setLevel(logging.INFO)

    logger.addHandler(handler)
    logger.propagate = False
    return logger

def run_nanoping(config, target, logfile, pidfile=None):
    """ exec nanoping """
    argdict = dict()
    argdict['path'] = config['nanoping']['cmd']
    argdict['log'] = logfile
    argdict['interface'] = config[target]['interface']
    argdict['duration'] = config['nanoping'].getint('duration')
    argdict['delay'] = config['nanoping'].getint('delay')
    argdict['silent'] = '--silent' if config['nanoping'].getboolean('silent') else ''
    argdict['ipaddr'] = config[target]['ipaddr']
    cmd_line = '{path} --client --interface {interface} --count {duration} --log {log} --delay {delay} {silent} {ipaddr}'.format_map(argdict)
    logger.info('exec nanoping command: {}'.format(cmd_line))

    if pidfile is not None:
        # ensure to kill old nanoping process
        try:
            with open(pidfile, 'r') as f:
                line = f.readline()
        except FileNotFoundError:
            logger.debug('no pidfile, ignore')
            line = None

        oldpid = None
        if line:
            try:
                oldpid = int(line)
            except:
                # format error? ignore
                pass
        if oldpid is not None:
            try:
                os.kill(oldpid, signal.SIGTERM)
                logger.info('old nanoping process(pid:{}) is killed'.format(oldpid))
            except:
                # process is not exist, just ignore
                pass
            os.remove(pidfile)

    proc = subprocess.Popen(shlex.split(cmd_line), stdout=subprocess.DEVNULL)
    if pidfile is not None:
        # record pid file
        logger.info('nanoping pid: {}'.format(proc.pid))
        with open(pidfile, 'w') as f:
            f.write(str(proc.pid))
    return proc

if __name__ == '__main__':
    args, config = config_parse_args()
    signal.signal(signal.SIGINT, handler)
    signal.signal(signal.SIGTERM, handler)
    pd_param()

    logger = setup_logger()

    # open nanoping log file
    if args.log is not None:
        log_file = args.log
    else:
        # generate log file name for this session
        now = datetime.now().strftime('%Y-%m-%dT%H:%M:%S')
        log_file = '{}/{}_{}.csv'.format(config['nanoping']['log_store'], args.interface, now)

    # exec nanoping
    if config['nanoping']['pidfile_path'] is not None:
        pidfile = '{}/{}.pid'.format(config['nanoping']['pidfile_path'], args.interface)
    else:
        pidfile = None
    proc = None
    if args.log is None:
        if not args.dry:
            proc = run_nanoping(config, args.interface, log_file, pidfile)
            while proc.poll() is not None:
                print ("waiting nanoping exec {}")
                time.sleep(0.5)
    
    # setup data collecter
    max_lines = config['option'].getint('lines')
    if not args.dry:
        nplog =  NPlog(filename=log_file, max_lines=max_lines)
    logger.debug('ready to read: {}'.format(log_file))

    # setup influxdb
    influx_config = config['influxdb']
    
    if not args.dry:
        db = tsdb(influx_config['db'], influx_config['host'], influx_config.getint('port'))
        db.create_db()
        if args.debug:
            db.check_db()

    # influxdb tag setting
    if_config = config[args.interface]
    influx_tag = dict()
    for tag in ['location', 'route']:
        if tag in if_config:
            influx_tag[tag] = if_config[tag]
    # influxdb measurement setting
    influx_measurement = if_config['measurement']

    logger.debug('influx setting: database: {}, measurement: {}, tag: {}'.format(influx_config['db'], influx_measurement, influx_tag))

    if args.dry:
        print('configururations are done. quit (dry-run-mode)')
        exit()

    count = 1
    influx_delay = config['option'].getint('delay')

    while True:
        try:
            df = nplog.next_df()
        except EOFError:
            print('end of file')
            break

        # prepare dataframe to put influxdb
        ndf = df.set_index('time')
        del ndf['t0r']
        del ndf['t1r']
        del ndf['t2r']
        del ndf['t3r']

        # store it
        result = db.insert(ndf, influx_measurement,  tags=influx_tag)
        if args.debug:
            print(ndf.head(2))
        else:
            if count == 1:
                print("{:>10}:".format(count), end='', flush=True)
            print('.', end='', flush=True)
            if (count % 80 == 0):
                print('\n{:>10}:'.format(count), end='', flush=True)

        if args.debug:
            print('influxdb write result:{}'.format(result))
        # query
        if args.debug:
            query_str = 'SELECT * FROM {} GROUP BY "location" ORDER BY time DESC LIMIT 5'.format(influx_measurement)
            result = db.query(query_str)
            print("Results: {}".format(result))
        del ndf
        count += 1
        # check nanoping status
        if proc is not None:
            retcode = proc.poll()
            if retcode is not None: # process is finished
                now = datetime.now().strftime('%Y-%m-%dT%H:%M:%S')
                logger.info('nanoping finished at {}'.format(now))
                proc = None
                # delete pid file tied to the process
                if pidfile is not None:
                    os.remove(pidfile)

        time.sleep(influx_delay)

