#!/usr/bin/env python
# -*- coding: utf-8 -*-

import abc
import json
import datetime
import logging
import hashlib
import uuid
import functools
from optparse import OptionParser
from http.server import HTTPServer, BaseHTTPRequestHandler

import re

import scoring

SALT = "Otus"
ADMIN_LOGIN = "admin"
ADMIN_SALT = "42"

OK = 200
BAD_REQUEST = 400
FORBIDDEN = 403
NOT_FOUND = 404
INVALID_REQUEST = 422
INTERNAL_ERROR = 500
ERRORS = {
    BAD_REQUEST: "Bad Request",
    FORBIDDEN: "Forbidden",
    NOT_FOUND: "Not Found",
    INVALID_REQUEST: "Invalid Request",
    INTERNAL_ERROR: "Internal Server Error",
}
UNKNOWN = 0
MALE = 1
FEMALE = 2
GENDERS = {
    UNKNOWN: "unknown",
    MALE: "male",
    FEMALE: "female",
}


class Field(object):
    def __init__(self, required=False, nullable=False):
        self.required = required
        self.nullable = nullable
        self.value = None

    def isvalid(self, fieldtype=type(None)):
        '''
        Parameters
        ----------
        fieldtype : class name, optional
            Type of field. The default is type(None).

        Returns
        -------
            boolean, value is field valid
            raises ValueError if string is invalid with error message
        '''
        self.valid = None

        # Check if field required
        if self.value is None:
            if self.required:
                # self.valid = Validity(False, "Required field is None.")
                raise ValueError('Required field is None.')
            else:
                self.valid = True
                return self.valid

        # Check if field nullable
        if self.isempty():
            if self.nullable:
                self.valid = True
                return self.valid
            else:
                raise ValueError("Not nullable field is empty.")

        # Check if field is fieldtype type
        if not isinstance(self.value, fieldtype):
            if isinstance(fieldtype, tuple):
                sfieldtype = " or ".join([f.__name__ for f in fieldtype])
            else:
                sfieldtype = fieldtype.__name__
            raise TypeError(f"Field must be {sfieldtype} type.")

        return True

    def isempty(self):
        return not self.value


class CharField(Field):
    def isvalid(self):
        return super().isvalid(fieldtype=str)


class EmailField(CharField):
    def isvalid(self):
        super().isvalid()
        if self.valid is None:
            # Check if field contains @
            if '@' in self.value:
                return True
            else:
                raise ValueError("Field must contain '@'.")
        return self.valid


class PhoneField(Field):
    rule = re.compile(r'^7\d{10}$')

    def isvalid(self):
        super().isvalid(fieldtype=(str, int))
        if self.valid is None:
            # Check if field starts with '7' and 11 digits length
            if not re.match(r'^7\d{10}$', str(self.value)):
                raise ValueError("Field must start with '7' and must be 11 digits length.")
            else:
                return True
        return self.valid


class DateField(Field):
    def isvalid(self):
        super().isvalid(fieldtype=str)
        if self.valid is None:
            # Check if field is date
            try:
                datetime.datetime.strptime(self.value, '%d.%m.%Y')
                return True
            except ValueError:
                raise ValueError("Field must be date in DD.MM.YYYY format.")
        return self.valid


class BirthDayField(DateField):
    def isvalid(self):
        super().isvalid()
        if self.valid is None:
            # Check if age is less than 70
            if self.age <= 70:
                return True
            else:
                raise ValueError("Age in field must be less than 70 years.")
        return self.valid

    @property
    def age(self):
        # date today
        td = datetime.date.today()
        # date of birth
        bd = datetime.datetime.strptime(self.value, '%d.%m.%Y').date()
        return td.year - bd.year + ((td.month, td.day) >= (bd.month, bd.day))


class GenderField(Field):
    def isvalid(self):
        super().isvalid(fieldtype=int)
        if self.valid is None:
            # Check if field is 0, 1 or 2
            if self.value in GENDERS:
                return True
            else:
                raise ValueError("Field must be 0, 1 or 2.")
        return self.valid

    def isempty(self):
        # 0 is not empty value
        if self.value == 0:
            return False
        return super().isempty()


class ClientIDsField(Field):
    def isvalid(self):
        super().isvalid(fieldtype=(list, tuple))
        if self.valid is None:
            # Check if each list item is int type
            valueitemisint = map(lambda z: isinstance(z, int), self.value)
            allvaluesisint = functools.reduce(lambda x, y: x and y, valueitemisint)
            if allvaluesisint:
                return True
            else:
                raise TypeError("Field must be an integer array.")
        return self.valid


class ArgumentsField(Field):
    def isvalid(self):
        return super().isvalid(fieldtype=dict)


class MetaRequest(type):
    '''
    Creates fields attribute as tuple with the Field type class attributes
    '''
    def __new__(cls, name, bases, body):
        body['fields'] = tuple(atr for atr in body if isinstance(body.get(atr), Field))
        return super().__new__(cls, name, bases, body)


class Request(metaclass=MetaRequest):
    context = {}
    store = None

    def __init__(self, request, ctx=None, store=None):
        for atr in self.fields:
            getattr(self, atr).value = request.get(atr, None)
        self.context = ctx
        self.store = store

    def isvalid(self):
        self.errorfields = []
        for atr in self.fields:
            try:
                getattr(self, atr).isvalid()
            except (ValueError, TypeError) as error:
                self.errorfields.append((atr, error))
        return not self.errorfields


class ClientsInterestsRequest(Request):
    client_ids = ClientIDsField(required=True, nullable=False)
    date = DateField(required=False, nullable=True)


class OnlineScoreRequest(Request):
    first_name = CharField(required=False, nullable=True)
    last_name = CharField(required=False, nullable=True)
    email = EmailField(required=False, nullable=True)
    phone = PhoneField(required=False, nullable=True)
    birthday = BirthDayField(required=False, nullable=True)
    gender = GenderField(required=False, nullable=True)

    pairs = [('phone', 'email'),
             ('first_name', 'last_name'),
             ('gender', 'birthday')]

    def isvalid(self):
        if super().isvalid():
            for pair in self.pairs:
                if not getattr(self, pair[0]).isempty() and not getattr(self, pair[1]).isempty():
                    return True
                else:
                    self.errorfields.append('"In request must be one pair with nonempty values."')
        return False


class MethodRequest(Request):
    account = CharField(required=False, nullable=True)
    login = CharField(required=True, nullable=True)
    token = CharField(required=True, nullable=True)
    arguments = ArgumentsField(required=True, nullable=True)
    method = CharField(required=True, nullable=False)

    @property
    def is_admin(self):
        return self.login.value == ADMIN_LOGIN


def check_auth(request):
    if request.is_admin:
        msg = datetime.datetime.now().strftime("%Y%m%d%H") + ADMIN_SALT
    else:
        msg = request.account.value + request.login.value + SALT
    digest = hashlib.sha512(msg.encode('utf-8')).hexdigest()
    if digest == request.token.value:
        return True
    return False


class OnlineScoreHandler(object):
    def getresponse(self, request, is_admin, context, store):
        requestobj = OnlineScoreRequest(request)
        logging.info("Method fields validation.")
        if not requestobj.isvalid():
            return requestobj.errorfields, INVALID_REQUEST
        logging.info('Method fields are valid.')

        logging.info("Context update.")
        ctx = {'has': []}
        for atr in requestobj.fields:
            if not getattr(requestobj, atr).isempty():
                ctx['has'].append(atr)
        context.update(ctx)

        logging.info('Getting response.')
        if is_admin:
            return {"score": 42}, OK

        return {"score": scoring.get_score(
                store=None,
                phone=requestobj.phone.value,
                email=requestobj.email.value,
                birthday=requestobj.birthday.value,
                gender=requestobj.gender.value,
                first_name=requestobj.first_name.value,
                last_name=requestobj.last_name.value
                )}, OK


class ClientsInterestsHandler(object):
    def getresponse(self, request, is_admin, context, store):
        requestobj = ClientsInterestsRequest(request)
        logging.info("Method fields validation.")
        if not requestobj.isvalid():
            return requestobj.errorfields, INVALID_REQUEST
        logging.info('Method fields are valid.')

        logging.info("Context update.")
        context.update({'nclients': len(requestobj.client_ids.value)})

        logging.info('Getting response.')
        result = {}
        for i in requestobj.client_ids.value:
            result[str(i)] = scoring.get_interests(store=None, cid=i)
        return result, OK


def method_handler(request, ctx, store):
    methoddict = {
        'online_score': OnlineScoreHandler,
        'clients_interests': ClientsInterestsHandler
    }

    # Request handler
    mrequest = MethodRequest(request['body'], ctx, store)

    logging.info("Request fields validation.")
    if not mrequest.isvalid():
        return mrequest.errorfields, INVALID_REQUEST
    logging.info('Request fields are valid.')

    logging.info('Authorization.')
    if not check_auth(mrequest):
        return "Authorization failed.", FORBIDDEN
    logging.info('Authorization success.')

    # Method handler
    if mrequest.method.value in methoddict:
        method = methoddict.get(mrequest.method.value)()
    else:
        return f"Method '{mrequest.method.value}' isn't found.", NOT_FOUND

    return method.getresponse(mrequest.arguments.value, mrequest.is_admin, ctx, store)


class MainHTTPHandler(BaseHTTPRequestHandler):
    router = {
        "method": method_handler
    }
    store = None

    def get_request_id(self, headers):
        return headers.get('HTTP_X_REQUEST_ID', uuid.uuid4().hex)

    def do_POST(self):
        response, code = {}, OK
        context = {"request_id": self.get_request_id(self.headers)}
        request = None
        data_string = None
        try:
            data_string = self.rfile.read(int(self.headers['Content-Length']))
            request = json.loads(data_string)
        except:
            code = BAD_REQUEST

        if request:
            path = self.path.strip("/")
            logging.info(f"{self.path}: {request} {context['request_id']}")
            if path in self.router:
                try:
                    response, code = self.router[path]({"body": request, "headers": self.headers}, context, self.store)
                except Exception as e:
                    logging.exception(f"Unexpected error: {e}")
                    code = INTERNAL_ERROR
            else:
                code = NOT_FOUND

        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        if code not in ERRORS:
            r = {"response": response, "code": code}
        else:
            r = {"error": response or ERRORS.get(code, "Unknown Error"), "code": code}
        context.update(r)
        logging.info(context)
        self.wfile.write(json.dumps(r).encode("ascii"))


if __name__ == "__main__":
    op = OptionParser()
    op.add_option("-p", "--port", action="store", type=int, default=8080)
    op.add_option("-l", "--log", action="store", default=None)
    (opts, args) = op.parse_args()
    logging.basicConfig(filename=opts.log, level=logging.INFO, format='[%(asctime)s] %(levelname).1s %(message)s',
                        datefmt='%Y.%m.%d %H:%M:%S'
                        )
    server = HTTPServer(("localhost", opts.port), MainHTTPHandler)
    logging.info("Starting server at {opts.port}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    server.server_close()
