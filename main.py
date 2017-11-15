import os
from flask import Flask, render_template, request, url_for
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import func, cast
from sqlalchemy.dialects.postgresql import ARRAY
from dodotable.schema import Table, Column, LinkedColumn

app = Flask(__name__)
assert 'DATABASE_URL' in os.environ
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL')
# app.config['SQLALCHEMY_ECHO'] = True
db = SQLAlchemy(app)


class Request(db.Model):
    """
    Tags:
        'xss'  : 'Cross-Site Scripting',
        'sqli' : 'SQL Injection',
        'csrf' : 'Cross-Site Request Forgery',
        'dos'  : 'Denial Of Service',
        'dt'   : 'Directory Traversal',
        'spam' : 'Spam',
        'id'   : 'Information Disclosure',
        'rfe'  : 'Remote File Execution',
        'lfi'  : 'Local File Inclusion'
    """

    id = db.Column(db.Integer, db.Sequence('request_id'), primary_key=True)
    ip = db.Column(db.String(16), index=True)
    method = db.Column(db.String(7))
    url = db.Column(db.String(2560))
    body = db.Column(db.String(10000))
    referrer = db.Column(db.String(10000))
    resp_status_code = db.Column(db.Integer)
    user_agent = db.Column(db.String(1000))
    datetime = db.Column(db.DateTime(timezone=False))
    tags = db.Column(ARRAY(db.String(7)))
    country = db.Column(db.String(100))


@app.cli.command()
def initdb():
    db.drop_all()
    db.create_all()


def endpoint_ip(ip):
    return url_for('requests', ip=ip)


@app.route('/unique_ip')
def unique_ip():
    query = db.session.query(func.distinct(Request.ip).label('ip'))
    table = Table(
        cls=query,
        label='Unique ip',
        columns=[
            LinkedColumn(attr='ip', label='ip', order_by=request.args.get('order_by', 'ip.asc'), endpoint=endpoint_ip),
        ],
        sqlalchemy_session=db.session
    )
    return render_template(
        'table.html',
        table=table.select(limit=request.args.get('limit', 100),
                           offset=request.args.get('offset', 0))
    )


@app.route('/unique_ip_hits')
def unique_ip_hits():
    query = db.session.query(func.distinct(Request.ip).label('ip'), Request.country, func.count(Request.ip).label('hits')).group_by(Request.ip, Request.country)
    table = Table(
        cls=query,
        label='Unique ip, country, hits',
        columns=[
            Column(attr='ip', label='ip', order_by=request.args.get('order_by', 'ip.asc')),
            Column(attr='country', label='country'),
            Column(attr='hits', label='hits'),
        ],
        sqlalchemy_session=db.session
    )
    return render_template(
        'table.html',
        table=table.select(limit=request.args.get('limit', 100),
                           offset=request.args.get('offset', 0))
    )


@app.route('/requests')
def requests():
    query = Request.query
    ip = request.args.get('ip')
    if ip:
        query = query.filter(Request.ip == ip)
    tags = request.args.get('tags')
    if tags:
        tags = list(set(map(lambda x: x.strip(), tags.split(','))))
        query = query.filter(Request.tags.contains(cast(tags, ARRAY(db.String(7)))))
    table = Table(
        cls=query,
        label='Request entries',
        columns=[
            Column(attr='ip', label=u'ip',
                   order_by=request.args.get('order_by')),
            Column(attr='method', label=u'method'),
            Column(attr='url', label=u'url'),
            Column(attr='body', label=u'body'),
            Column(attr='referrer', label=u'referrer'),
            Column(attr='resp_status_code', label=u'response status code'),
            Column(attr='user_agent', label=u'user agent'),
            Column(attr='datetime', label=u'datetime'),
            Column(attr='country', label=u'country'),
            Column(attr='tags', label=u'tags'),
        ],
        sqlalchemy_session=db.session
    )
    return render_template(
        'table.html',
        table=table.select(limit=request.args.get('limit', 100),
                           offset=request.args.get('offset', 0))
    )


@app.route('/')
def index():
    links = [
        ('list of unique IP addresses', url_for('unique_ip')),
        ('list of unique IP addresses with country and number of hits', url_for('unique_ip_hits')),
        ('list of all activity per IP address (can be filtered by this IP)', url_for('unique_ip')),
        ('detect SQLi with found entries', url_for('requests', tags='sqli')),
        ('detect remote file inclusion with found entries', url_for('requests', tags='rfe')),
        ('detect web shells with found entries', url_for('requests', tags='lfi'))
    ]
    return render_template('index.html', links=links)
