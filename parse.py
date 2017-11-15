import os
import re
import sys
import json
import logging
import datetime
import multiprocessing as mp
import maxminddb
from main import db, Request

logger = logging.getLogger("Log parse")

maxminddb_path = 'GeoLite2-Country_20171107/GeoLite2-Country.mmdb'

reader = maxminddb.open_database(maxminddb_path)

log_line_regex = re.compile(r'^(\d+-\d+-\d+) (\d+:\d+:\d+) (\d+.\d+.\d+.\d+) (\S+) (\S+) (.+) (\d+) (\S+) (\d+.\d+.\d+.\d+) (.+) (http.+) (\d+) (\d+) (\d+) (\d+)$')

with open('default_filter.json', 'r') as f:
    filters = json.loads(f.read())['filters']['filter']
    for _filter in filters:
        try:
            _filter['rule'] = re.compile(_filter['rule'])
        except:
            logger.info('Invalid rule %s' % _filter['rule'])


def analyzer(url):
    tags = []
    for _filter in filters:
        if _filter['rule'].search(url):
            tags.extend(_filter['tags']['tag'])
    return tags


def processfile(filename, start=0, stop=0):
    with open(filename, 'r') as fh:
        fh.seek(start)
        if stop != 0:
            lines = fh.readlines(stop - start)
            for line in lines:
                m = log_line_regex.match(line)
                if m:
                    date, time, _, method, url, body, _, _, ip, user_agent, referrer, resp_status_code, _, _, _ = m.groups()
                    try:
                        country = reader.get(ip)
                        if country and 'country' in country:
                            country = country['country']['names']['en']
                        else:
                            country = 'Unknown'
                    except ValueError:
                        country = 'Unknown'
                    r = Request(
                        ip=ip,
                        method=method,
                        url=url,
                        body=body,
                        referrer=referrer,
                        resp_status_code=resp_status_code,
                        user_agent=user_agent,
                        datetime=datetime.datetime.strptime("%s %s" % (date, time), '%Y-%m-%d %H:%M:%S'),
                        tags=analyzer(url),
                        country=country
                    )
                    db.session.add(r)
                else:
                    logger.info("Can't parse this: " + line)
            db.session.commit()


if __name__ == '__main__':

    filename = sys.argv[1]
    cpu_count = mp.cpu_count()
    # get file size and set chuck size
    filesize = os.path.getsize(filename)
    split_size = 10 * 1024 * 1024

    # determine if it needs to be split
    if filesize > split_size:

        # create pool, initialize chunk start location (cursor)
        pool = mp.Pool(cpu_count)
        cursor = 0
        with open(filename, 'r') as fh:

            # for every chunk in the file...
            for chunk in range(filesize // split_size):

                # determine where the chunk ends, is it the last one?
                if cursor + split_size > filesize:
                    end = filesize
                else:
                    end = cursor + split_size
                    # seek to end of chunk and read next line to ensure you
                    # pass entire lines to the processfile function
                    fh.seek(end)
                    fh.readline()

                    # get current file location
                    end = fh.tell()

                    # add chunk to process pool, save reference to get results
                    proc = pool.apply_async(processfile, args=[filename, cursor, end])

                    # setup next chunk
                    cursor = end

        # close and wait for pool to finish
        pool.close()
        pool.join()

    else:
        processfile(filename)
