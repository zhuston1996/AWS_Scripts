#!/usr/bin/env python3
import boto3
import botocore.exceptions
import time
import dateutil.parser
from datetime import datetime
import csv
import sys
import io
import argparse
import jinja2
import logging
from operator import itemgetter
from multiprocessing.pool import ThreadPool
from pprint import pprint
# import smtplib
# from email.mime.multipart import MIMEMultipart
# from email.mime.text import MIMEText
import json


logging.basicConfig(level=logging.WARN,
                    format='%(asctime)s - %(levelname)s - %(message)s')
logging.getLogger('__main__').setLevel(logging.INFO)
logging.getLogger('UserReport').setLevel(logging.INFO)
log = logging.getLogger(__name__)
args = None


def main(argv):
    global args
    p = argparse.ArgumentParser(description='Generate AWS IAM User Report')
    p = add_args(p)
    args = p.parse_args(argv)
    if args.verbose:
        logging.getLogger('__main__').setLevel(logging.DEBUG)
        logging.getLogger('UserReport').setLevel(logging.DEBUG)

    reports = get_reports()
    report_html = html_report(reports)

    if args.smtp_to:
        if args.fmt_json:
            email_report(args, report_html, json.dumps(
                reports, cls=ReportEncoder, indent=2))
        else:
            email_report(args, report_html)
    else:
        if args.fmt_json:
            log.debug('Printing JSON report to STDOUT')
            print(json.dumps(reports, cls=ReportEncoder, indent=2))
        else:
            log.debug('Printing HTML report to STDOUT')
            print(report_html)


def add_args(p):
    p.add_argument('--aws-credentials', '-c',
                   help='AWS Credentials as: SOME_REPORT_NAME,ACCESS_KEY_ID,SECRET_ACCESS_KEY', dest='aws_credentials',
                   nargs='+', type=aws_credentials)
    p.add_argument('--smtp-server', help='SMTP Server Hostname',
                   dest='smtp_server', type=str, default='localhost')
    p.add_argument('--smtp-port', help='SMTP Server Port',
                   dest='smtp_port', type=int, default=25)
    p.add_argument('--smtp-ssl', help='SMTP Server uses SSL (not STARTTLS)', dest='smtp_ssl', action='store_true',
                   default=False)
    p.add_argument('--smtp-login', help='SMTP Server Login',
                   dest='smtp_login', type=str)
    p.add_argument('--smtp-password', help='SMTP Server Password',
                   dest='smtp_password', type=str)
    p.add_argument('--smtp-from', help='Email From',
                   dest='smtp_from', type=str, default='noreply@example.com')
    p.add_argument('--smtp-to', help='Email To',
                   dest='smtp_to', type=str, nargs='+')
    p.add_argument('--smtp-subject', help='Email Subject', dest='smtp_subject', type=str,
                   default='AWS User Report')
    p.add_argument('--verbose', '-v', help='Verbose logging',
                   dest='verbose', action='store_true', default=False)
    p.add_argument('--json', help='Dump Report as JSON',
                   dest='fmt_json', action='store_true', default=False)
    p.add_argument('--header', help='Report Header',
                   dest='report_header', type=str, default='')
    p.add_argument('--footer', help='Report Footer',
                   dest='report_footer', type=str, default='')
    p.add_argument('--wait-days',
                   help='Days after account creation before an account that never logged in is considered dead (Default: 60)',
                   dest='wait_days', type=int, default=60)
    p.add_argument('--alert-days', help='Days of inactivity after which an account is considered dead (Default: 365)',
                   dest='alert_days', type=int, default=365)
    return p


# meh... don't care about email reporting at this time.
# def email_report(args, report_html,
#                  report_plain='Unsupported Client. Please view with an Email Client that supports HTML.'):
#     log.debug('Sending Report by Email via {}:{}'.format(
#         args.smtp_server, args.smtp_port))

#     msg = MIMEMultipart('alternative')
#     msg['Subject'] = args.smtp_subject
#     msg['From'] = args.smtp_from
#     msg['To'] = ', '.join(args.smtp_to)
#     plain = MIMEText(report_plain, 'plain')
#     html = MIMEText(report_html, 'html')

#     msg.attach(plain)
#     msg.attach(html)

#     if args.smtp_ssl:
#         s = smtplib.SMTP_SSL('{}:{}'.format(args.smtp_server, args.smtp_port))
#     else:
#         s = smtplib.SMTP('{}:{}'.format(args.smtp_server, args.smtp_port))
#     if args.smtp_login and args.smtp_password:
#         s.login(args.smtp_login, args.smtp_password)
#     s.sendmail(args.smtp_from, args.smtp_to, msg.as_string())
#     log.info('Sent Email to {}'.format(', '.join(args.smtp_to)))
#     s.quit()


def get_reports():
    reports = list()
    if args.aws_credentials:
        for name, access_key_id, secret_access_key in args.aws_credentials:
            ur = UserReport(name, access_key_id, secret_access_key)
            reports.append(ur.report())
    else:
        ur = UserReport('AWS Account')
        reports.append(ur.report())
    return reports


def html_report(reports):
    page_template = """<!doctype html>
    <html lang="en">
    <head>
        <meta charset="utf-8">
        <title>AWS User Report</title>
    </head>
    {{ header }}
    <body style="font-family:'Source Sans Pro','Helvetica Neue',Helvetica,Arial,sans-serif;font-style:normal;font-weight:400;text-transform:none;text-shadow:none;text-decoration:none;text-rendering:optimizelegibility;color: #000000;">
        {{ body }}
    </body>
    {{ footer }}
    </html>
    """
    html_reports = list()
    html = jinja2.Template(page_template)
    for report in reports:
        html_reports.append(report2html(report['name'], report['report']))

    log.debug('Assembling final HTML report')
    return html.render(body='<br/><br/><br/>'.join(html_reports), header=args.report_header, footer=args.report_footer)


def aws_credentials(credentials):
    try:
        name, access_key_id, secret_access_key = map(
            str, credentials.split(',', 2))
        return name, access_key_id, secret_access_key
    except:
        raise argparse.ArgumentTypeError(
            "AWS Credentials must be given in the form of access_key_id,secret_access_key")


def report2html(name, report):
    img = {'n/a': '&#x2796;',
           'never': '&#x2716;',
           'true': '&#x2714;',
           'false': '&#x2796;'
           }

    # Need to duplicate style elements for certain Email clients
    report_template = """    <h3>{{ name }}</h3>
    <table style="border: 1px solid black;border-collapse: collapse;">
        <tr class="center">
            <td style="padding-left: 3px; padding-right: 3px;border: 1px solid black;border-collapse: collapse;"><b>User</b></td>
            <td style="padding-left: 3px; padding-right: 3px;border: 1px solid black;border-collapse: collapse;"><b>Last active</b></td>
            <td style="padding-left: 3px; padding-right: 3px;border: 1px solid black;border-collapse: collapse;"><b>Created</b></td>
            <td style="padding-left: 3px; padding-right: 3px;border: 1px solid black;border-collapse: collapse;"><b>Access Key(s)</b></td>
            <td style="padding-left: 3px; padding-right: 3px;border: 1px solid black;border-collapse: collapse;"><b>Password</b></td>
            <td style="padding-left: 3px; padding-right: 3px;border: 1px solid black;border-collapse: collapse;"><b>Last changed</b></td>
            <td style="padding-left: 3px; padding-right: 3px;border: 1px solid black;border-collapse: collapse;"><b>Groups</b></td>
            <td style="padding-left: 3px; padding-right: 3px;border: 1px solid black;border-collapse: collapse;"><b>Policies</b></td>
            <td style="padding-left: 3px; padding-right: 3px;border: 1px solid black;border-collapse: collapse;"><b>Last Service used by an Access Key</b></td>
        </tr>
        {%- for row in rows %}
        <tr style="background-color: {{ row.color }}">
            <td style="padding-left: 3px; padding-right: 3px;border: 1px solid black;border-collapse: collapse;white-space:nowrap">{{ row.user|e }}</td>
            <td style="padding-left: 3px; padding-right: 3px;border: 1px solid black;border-collapse: collapse;white-space:nowrap; text-align: {{ row.active_align }};">{{ row.active }}</td>
            <td style="padding-left: 3px; padding-right: 3px;border: 1px solid black;border-collapse: collapse;white-space:nowrap; text-align: right;">{{ row.created }}</td>
            <td style="padding-left: 3px; padding-right: 3px;border: 1px solid black;border-collapse: collapse;text-align: center;">{{ row.access_key }}</td>
            <td style="padding-left: 3px; padding-right: 3px;border: 1px solid black;border-collapse: collapse;text-align: center;">{{ row.password }}</td>
            <td style="padding-left: 3px; padding-right: 3px;border: 1px solid black;border-collapse: collapse;white-space:nowrap; text-align: {{ row.password_changed_align }};">{{ row.password_changed }}</td>
            <td style="padding-left: 3px; padding-right: 3px;border: 1px solid black;border-collapse: collapse;">{{ row.groups }}</td>
            <td style="padding-left: 3px; padding-right: 3px;border: 1px solid black;border-collapse: collapse;">{{ row.policies }}</td>
            <td style="padding-left: 3px; padding-right: 3px;border: 1px solid black;border-collapse: collapse;">{{ row.last_service }}</td>
        </tr>
        {%- endfor %}
    </table>
"""
    rows = list()
    # we get a gradient from green over yellow to red and then
    # mix it with white to make it easy on the eyes
    mix_color = (255, 255, 255)
    color_gradient = color_mix(gyr_gradient(), mix_color)

    # how many days after account creation before
    # an account that never logged in is considered dead
    initial_wait_days = args.wait_days
    alert_days = args.alert_days  # anything after this will be considered dead

    for user in sorted(report, key=itemgetter('user')):
        r = {
            'user': user['user'],
            'active': '',
            'active_align': 'right',
            'created': '',
            'access_key': '',
            'password': '',
            'password_changed': '',
            'password_changed_align': 'right',
            'groups': ', '.join(user['groups']),
            'policies': ', '.join(user['policies']),
            'last_service': '',
            'color': '#{:02x}{:02x}{:02x}'.format(*color_gradient[-1])
        }
        try:
            last_active = max(filter(None, [user['access_key_1_last_used_date'], user['access_key_2_last_used_date'],
                                            user['password_last_used']]))
            r['active'] = days_ago(last_active)
            last_active_days = (datetime.utcnow() - last_active).days
            color_index = round(
                remap(last_active_days, 0, alert_days, 0, len(color_gradient) - 1))
            r['color'] = '#{:02x}{:02x}{:02x}'.format(
                *color_gradient[color_index])
        except ValueError:
            r['active'] = img['never']
            r['active_align'] = 'center'

        if user['user'] == '<root_account>':
            r['color'] = '#{:02x}{:02x}{:02x}'.format(*color_gradient[0])

        if (datetime.utcnow() - user['user_creation_time']).days < initial_wait_days:
            r['color'] = '#{:02x}{:02x}{:02x}'.format(*color_gradient[0])

        if user['password_last_changed']:
            if user['user_creation_time'].date() == user['password_last_changed'].date():
                r['password_changed_align'] = 'center'
                r['password_changed'] = img['never']
            else:
                r['password_changed'] = days_ago(user['password_last_changed'])
        else:
            r['password_changed_align'] = 'center'
            r['password_changed'] = img['never'] if user['password_enabled'] else img['n/a']

        r['created'] = days_ago(user['user_creation_time'])

        r['access_key'] = img['true'] if user['access_key_1_active'] or user['access_key_2_active'] else img['false']
        r['password'] = img['true'] if user['password_enabled'] else img['false']
        r['last_service'] = last_service(user)

        rows.append(r)
    html = jinja2.Template(report_template)
    log.debug('Creating HTML report snippet')
    return html.render(rows=rows, name=name)


def last_service(user):
    compare = False
    key_1 = False
    key_2 = False
    if user['access_key_1_last_used_date'] and user['access_key_2_last_used_date']:
        compare = True
    if user['access_key_1_last_used_service'] \
            and user['access_key_1_last_used_region'] \
            and user['access_key_1_last_used_date']:
        key_1 = True
    if user['access_key_2_last_used_service'] \
            and user['access_key_2_last_used_region'] \
            and user['access_key_2_last_used_date']:
        key_2 = True

    if compare and key_1 and key_2:
        if user['access_key_1_last_used_date'] > user['access_key_2_last_used_date']:
            last_service_str = '{} in {}, {}'.format(user['access_key_1_last_used_service'],
                                                     user['access_key_1_last_used_region'],
                                                     days_ago(user['access_key_1_last_used_date']))
        else:
            last_service_str = '{} in {}, {}'.format(user['access_key_2_last_used_service'],
                                                     user['access_key_2_last_used_region'],
                                                     days_ago(user['access_key_2_last_used_date']))
    elif key_1:
        last_service_str = '{} in {}, {}'.format(user['access_key_1_last_used_service'],
                                                 user['access_key_1_last_used_region'],
                                                 days_ago(user['access_key_1_last_used_date']))

    elif key_2:
        last_service_str = '{} in {}, {}'.format(user['access_key_2_last_used_service'],
                                                 user['access_key_2_last_used_region'],
                                                 days_ago(user['access_key_2_last_used_date']))
    else:
        last_service_str = ''

    return last_service_str


def days_ago(dt):
    now = datetime.utcnow()
    days = (now - dt).days
    if days == 0:
        return 'today'
    elif days == 1:
        return 'yesterday'
    else:
        return '{} days ago'.format(days)


def color_mix(in_color, mix_color):
    def mix(in_color, mix_color):
        return tuple(round(sum(x) / 2) for x in zip(in_color, mix_color))
    if isinstance(in_color, list):
        out_colors = list()
        for color in in_color:
            out_colors.append(mix(color, mix_color))
        return out_colors
    else:
        return mix(in_color, mix_color)


def gyr_gradient(increment=1):
    r = 0
    g = 255
    b = 0
    gradient = list()
    gradient.append((r, g, b))

    if increment < 1:
        increment = 1
    elif increment > 255:
        increment = 255
    while r < 255:
        r += increment
        if r > 255:
            r = 255
        gradient.append((r, g, b))
    while g > 0:
        g -= increment
        if g < 0:
            g = 0
        gradient.append((r, g, b))
    return gradient


def remap(x, in_min, in_max, out_min, out_max, min_max_cutoff=True):
    if min_max_cutoff:
        if x < in_min:
            x = in_min
        elif x > in_max:
            x = in_max
    return (x - in_min) * (out_max - out_min) / (in_max - in_min) + out_min


class UserReport:
    def __init__(self, name, access_key_id=None, secret_access_key=None):
        self.name = name
        self._access_key_id = access_key_id
        self._secret_access_key = secret_access_key
        self.log = logging.getLogger(__name__)

    def report(self):
        self.log.info('Generating Report "{}"'.format(self.name))
        session = boto3.session.Session(aws_access_key_id=self._access_key_id,
                                        aws_secret_access_key=self._secret_access_key)
        iam = session.client('iam')
        complete = False
        while not complete:
            resp = iam.generate_credential_report()
            complete = resp['State'] == 'COMPLETE'
            time.sleep(1)

        report = iam.get_credential_report()

        self.log.debug('Processing IAM Report generated {}'.format(
            report['GeneratedTime']))

        if report['ReportFormat'] != 'text/csv':
            raise RuntimeError(
                'Unknown Format {}'.format(report['ReportFormat']))

        # report_date = report['GeneratedTime']
        report_csv = io.StringIO(report['Content'].decode('utf-8'))
        csv_reader = csv.DictReader(report_csv)

        users = list(csv_reader)
        p = ThreadPool(50)
        return {'name': self.name,
                'report': list(p.map(self.add_user_properties, users))
                }

    def add_user_properties(self, user):
        self.log.debug(
            'Assembling Properties for user {}'.format(user['user']))

        datetime_keys = ['access_key_1_last_rotated', 'access_key_1_last_used_date', 'access_key_2_last_rotated',
                         'access_key_2_last_used_date', 'cert_1_last_rotated', 'cert_2_last_rotated',
                         'password_last_changed', 'password_last_used', 'password_next_rotation', 'user_creation_time']

        bool_keys = ['access_key_1_active', 'access_key_2_active', 'cert_1_active', 'cert_2_active', 'mfa_active',
                     'password_enabled']

        str_keys = ['access_key_1_last_used_region', 'access_key_1_last_used_service', 'access_key_2_last_used_region',
                    'access_key_2_last_used_service']

        err_vals = ['N/A', 'no_information', 'not_supported']

        for key in datetime_keys:
            try:
                user[key] = dateutil.parser.parse(user[key]).replace(
                    tzinfo=None) if user[key] not in err_vals else None
            except Exception as e:
                self.log.error('Failed to parse date {}'.format(user[key]))

        for key in bool_keys:
            user[key] = user[key] == 'true'

        if user['user'] == '<root_account>':
            user['password_enabled'] = True

        for key in str_keys:
            if user[key] in err_vals:
                user[key] = None

        user['groups'] = list()
        user['policies'] = list()
        try:
            user['groups'] = self.user_groups(user['user'])
            user['policies'] = self.user_policies(user['user'])
        except botocore.exceptions.ClientError as e:
            if '(NoSuchEntity)' in str(e):
                user['user'] += ' [DELETED]'
                pass
            else:
                raise

        return user

    def user_groups(self, user):
        if user == '<root_account>':
            return []
        self.log.debug('Fetching Groups for user {}'.format(user))
        session = boto3.session.Session(aws_access_key_id=self._access_key_id,
                                        aws_secret_access_key=self._secret_access_key)
        iam = session.client('iam')
        complete = False
        marker = None
        ui = []
        while not complete:
            if marker:
                items = iam.list_groups_for_user(UserName=user, Marker=marker)
            else:
                items = iam.list_groups_for_user(UserName=user)
            if items['IsTruncated']:
                marker = items['Marker']
            else:
                complete = True

            for group in items['Groups']:
                ui.append(group['GroupName'])
        return ui

    def user_policies(self, user):
        if user == '<root_account>':
            return []
        self.log.debug('Fetching Policies for user {}'.format(user))
        session = boto3.session.Session(aws_access_key_id=self._access_key_id,
                                        aws_secret_access_key=self._secret_access_key)
        iam = session.client('iam')
        complete = False
        marker = None
        ui = []
        while not complete:
            if marker:
                items = iam.list_user_policies(UserName=user, Marker=marker)
            else:
                items = iam.list_user_policies(UserName=user)
            if items['IsTruncated']:
                marker = items['Marker']
            else:
                complete = True

            ui.extend(items['PolicyNames'])
        return ui


class ReportEncoder(json.JSONEncoder):
    def default(self, o):
        if isinstance(o, datetime):
            return o.isoformat()
        return super().default(self, o)


if __name__ == "__main__":
    main(sys.argv[1:])
