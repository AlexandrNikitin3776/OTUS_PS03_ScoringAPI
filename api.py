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
import collections

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

Validity = collections.namedtuple("Validity", "isvalid error")


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
        namedtuple Validity(isvalid, error)
            isvalid - boolean, value is field valid
            error  - string, validation error
        '''
        self.valid = Validity(None, None)

        # Check if field required
        if self.value is None:
            if self.required:
                self.valid = Validity(False, "Required field is None.")
                return self.valid
            else:
                self.valid = Validity(True, None)
                return self.valid

        # Check if field nullable
        if self.isempty():
            if self.nullable:
                self.valid = Validity(True, None)
                return self.valid
            else:
                self.valid = Validity(False, "Not nullable field is empty.")
                return self.valid

        # Check if field is fieldtype type
        if not isinstance(self.value, fieldtype):
            if isinstance(fieldtype, tuple):
                sfieldtype = " or ".join([f.__name__ for f in fieldtype])
            else:
                sfieldtype = fieldtype.__name__
            self.valid = Validity(False, "Field must be %s type." % sfieldtype)
            return self.valid

        return Validity(True, None)

    def isempty(self):
        return not self.value


class CharField(Field):
    def isvalid(self):
        return super().isvalid(fieldtype=str)


class EmailField(CharField):
    def isvalid(self):
        super().isvalid()
        if self.valid.isvalid is None:
            # Check if field contains @
            if '@' in self.value:
                return Validity(True, None)
            else:
                self.valid = Validity(False, "Field must contain '@'.")
        return self.valid


class PhoneField(Field):
    rule = re.compile(r'^7\d{10}$')

    def isvalid(self):
        super().isvalid(fieldtype=(str, int))
        if self.valid.isvalid is None:
            # Check if field starts with '7' and 11 digits length
            if not re.match(r'^7\d{10}$', str(self.value)):
                self.valid = Validity(False, "Field must start with '7' and must be 11 digits length.")
            else:
                return Validity(True, None)
        return self.valid


class DateField(Field):
    def isvalid(self):
        super().isvalid(fieldtype=str)
        if self.valid.isvalid is None:
            # Check if field is date
            try:
                datetime.datetime.strptime(self.value, '%d.%m.%Y')
                return Validity(True, None)
            except ValueError:
                self.valid = Validity(False, "Field must be date in DD.MM.YYYY format.")
        return self.valid


class BirthDayField(DateField):
    def isvalid(self):
        super().isvalid()
        if self.valid.isvalid is None:
            # Check if age is less than 70
            if self.age <= 70:
                return Validity(True, None)
            else:
                self.valid = Validity(False, "Age in field must be less than 70 years.")
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
        if self.valid.isvalid is None:
            # Check if field is 0, 1 or 2
            if self.value in GENDERS:
                return Validity(True, None)
            else:
                self.valid = Validity(False, "Field must be 0, 1 or 2.")
        return self.valid

    def isempty(self):
        # 0 is not empty value
        if self.value == 0:
            return False
        return super().isempty()


class ClientIDsField(Field):
    def isvalid(self):
        super().isvalid(fieldtype=(list, tuple))
        if self.valid.isvalid is None:
            # Check if each list item is int type
            valueitemisint = map(lambda z: isinstance(z, int), self.value)
            allvaluesisint = functools.reduce(lambda x, y: x and y, valueitemisint)
            if allvaluesisint:
                return Validity(True, None)
            else:
                self.valid = Validity(False, "Field must be an integer array.")
        return self.valid


class ArgumentsField(Field):
    def isvalid(self):
        return super().isvalid(fieldtype=dict)


class Request(object):
    context = {}
    store = None

    def __init__(self, request, ctx=None, store=None):
        for atr in dir(self):
            if isinstance(getattr(self, atr), Field):
                getattr(self, atr).value = request.get(atr, None)
        self.context = ctx
        self.store = store

    def isvalid(self):
        self.errorfields = []
        for atr in dir(self):
            if isinstance(getattr(self, atr), Field):
                valid, error = getattr(self, atr).isvalid()
                if not valid:
                    self.errorfields.append((atr, error))
        return not self.errorfields


class ClientsInterestsRequest(Request):
    client_ids = ClientIDsField(required=True, nullable=False)
    date = DateField(required=False, nullable=True)

    def getresponse(self, *args):
        result = {}
        for i in self.client_ids.value:
            result[str(i)] = scoring.get_interests(store=None, cid=i)
        self.context.update({'nclients': len(self.client_ids.value)})
        return result


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

    def getresponse(self, is_admin, *args):
        # Context update
        ctx = {'has': []}
        for atr in dir(self):
            if isinstance(getattr(self, atr), Field):
                if not getattr(self, atr).isempty():
                    ctx['has'].append(atr)
        self.context.update(ctx)

        if is_admin:
            return {"score": 42}

        return {"score": scoring.get_score(
                store=None,
                phone=self.phone.value,
                email=self.email.value,
                birthday=self.birthday.value,
                gender=self.gender.value,
                first_name=self.first_name.value,
                last_name=self.last_name.value
                )}


class MethodRequest(Request):
    account = CharField(required=False, nullable=True)
    login = CharField(required=True, nullable=True)
    token = CharField(required=True, nullable=True)
    arguments = ArgumentsField(required=True, nullable=True)
    method = CharField(required=True, nullable=False)

    methoddict = {
        'online_score': OnlineScoreRequest,
        'clients_interests': ClientsInterestsRequest
    }

    def __init__(self, request, ctx, store):
        super().__init__(request['body'], ctx, store)

    @property
    def is_admin(self):
        return self.login.value == ADMIN_LOGIN

    def getmethod(self):
        # Metod definition
        handler = self.methoddict.get(self.method.value)
        if handler:
            return handler(self.arguments.value, self.context, self.store)


def check_auth(request):
    if request.is_admin:
        msg = datetime.datetime.now().strftime("%Y%m%d%H") + ADMIN_SALT
    else:
        msg = request.account.value + request.login.value + SALT
    digest = hashlib.sha512(msg.encode('utf-8')).hexdigest()
    if digest == request.token.value:
        return True
    return False


def method_handler(request, ctx, store):
    # Request handler
    mrequest = MethodRequest(request, ctx, store)

    logging.info("Request fields validation.")
    if not mrequest.isvalid():
        return mrequest.errorfields, INVALID_REQUEST, mrequest.context
    logging.info('Request fields are valid.')

    logging.info('Authorization.')
    if not check_auth(mrequest):
        return "Authorization failed.", FORBIDDEN, mrequest.context
    logging.info('Authorization success.')

    # Method handler
    method = mrequest.getmethod()
    if method is None:
        return "Method '%s' isn't found." % mrequest.method.value, NOT_FOUND, mrequest.context

    # checking method fields validity
    logging.info("Method fields validation.")
    if not method.isvalid():
        return method.errorfields, INVALID_REQUEST, method.context
    logging.info('Method fields are valid.')

    return method.getresponse(mrequest.is_admin), OK, method.context


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
            logging.info("%s: %s %s" % (self.path, request, context["request_id"]))
            if path in self.router:
                try:
                    response, code, context = self.router[path](
                        {"body": request, "headers": self.headers},
                        context, self.store
                    )
                except Exception as e:
                    logging.exception("Unexpected error: %s" % e)
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
    logging.info("Starting server at %s" % opts.port)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    server.server_close()
