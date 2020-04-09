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
        # Check if field required
        if self.value is None:
            if self.required:
                logging.error(
                    "Required field '%s' is None." % type(self).__name__
                )
                return False
            else:
                return True

        # Check if field nullable
        if self.isempty():
            if self.nullable:
                return True
            else:
                logging.error(
                    "Not nullable field '%s' is empty." % type(self).__name__
                )
                return False

        # Check if field is fieldtype type
        if not isinstance(self.value, fieldtype):
            if isinstance(fieldtype, tuple):
                sfieldtype = " or ".join([f.__name__ for f in fieldtype])
            else:
                sfieldtype = fieldtype.__name__
            logging.error(
                "Field '%s' = %s must be %s." % (
                    type(self).__name__,
                    self.value,
                    sfieldtype
                )
            )
            return False

    def isempty(self):
        return not self.value


class CharField(Field):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def isvalid(self):
        validity = super().isvalid(fieldtype=str)
        if validity is None:
            return True
        return validity


class EmailField(Field):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def isvalid(self):
        validity = super().isvalid(fieldtype=str)
        if validity is None:
            if '@' in self.value:
                return True
            else:
                logging.error(
                    "Field '%s' must contain '@'." % type(self).__name__
                )
            return False
        return validity


class PhoneField(Field):
    rule = re.compile(r'^7\d{10}$')

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def isvalid(self):
        validity = super().isvalid(fieldtype=(str, int))
        if validity is None:
            if not re.match(r'^7\d{10}$', str(self.value)):
                logging.error(
                    "Field '%s' must start with '7' and "
                    "must be 11 digits length." % type(self).__name__
                )
                return False
            else:
                return True
        return validity


class DateField(Field):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def isvalid(self):
        validity = super().isvalid(fieldtype=str)
        if validity is None:
            try:
                datetime.datetime.strptime(self.value, '%d.%m.%Y')
            except ValueError:
                logging.error(
                    "Field '%s' must be date in DD.MM.YYYY format."
                    % type(self).__name__
                )
                return False
            return True
        return validity


class BirthDayField(Field):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def isvalid(self):
        validity = super().isvalid(fieldtype=str)
        if validity is None:
            try:
                datetime.datetime.strptime(self.value, '%d.%m.%Y')
            except ValueError:
                logging.error(
                    "Field '%s' must be date in DD.MM.YYYY format."
                    % type(self).__name__
                )
                return False
            if self.age <= 70:
                return True
            else:
                logging.error(
                    "Age in field '%s' must be less than 70 years."
                    % type(self).__name__
                )
                return False
        return validity

    @property
    def age(self):
        # date today
        td = datetime.date.today()
        # date of birth
        bd = datetime.datetime.strptime(self.value, '%d.%m.%Y').date()
        return td.year - bd.year + ((td.month, td.day) >= (bd.month, bd.day))


class GenderField(Field):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def isvalid(self):
        validity = super().isvalid(fieldtype=int)
        if validity is None:
            if self.value in GENDERS:
                return True
            else:
                logging.error(
                    "Field '%s' must be 0, 1 or 2." % type(self).__name__
                )
                return False
        return validity

    def isempty(self):
        if self.value == 0:
            return False
        return super().isempty()


class ClientIDsField(Field):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def isvalid(self):
        validity = super().isvalid(fieldtype=(list, tuple))
        if validity is None:
            if functools.reduce(
                lambda x, y: x and y,
                map(lambda z: isinstance(z, int), self.value)
            ):
                return True
            else:
                logging.error(
                    "Field '%s' must integer array." % type(self).__name__
                )
                return False
        return validity


class ArgumentsField(Field):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def isvalid(self):
        validity = super().isvalid(fieldtype=dict)
        if validity is None:
            return True
        return validity


class PostRequest(object):
    errorfields = []
    context = None
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
                if not getattr(self, atr).isvalid():
                    self.errorfields.append(atr)
        return not self.errorfields

    def geterrorresponse(self):
        if len(self.errorfields) > 1:
            return "Fields " + ", ".join(self.errorfields) + " are invalid."
        if len(self.errorfields) == 1:
            return "Field " + self.errorfields[0] + " is invalid."


class ClientsInterestsRequest(PostRequest):
    client_ids = ClientIDsField(required=True, nullable=False)
    date = DateField(required=False, nullable=True)

    def getresponse(self, is_admin):
        result = {}
        for i in self.client_ids.value:
            result[str(i)] = scoring.get_interests(
                    store=None,
                    cid=i
            )
        self.context = {'nclients': len(self.client_ids.value)}
        return result


class OnlineScoreRequest(PostRequest):
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
                if not getattr(self, pair[0]).isempty() \
                        and not getattr(self, pair[1]).isempty():
                    return True
                else:
                    logging.error(
                        "In request %s have to be one pair with "
                        "nonempty values." % type(self).__name__)
                    self.errorfields.append('empty pairs')
        return False

    def geterrorresponse(self):
        if self.errorfields == 'empty pairs':
            return "There are not non empty field pairs."
        return super().geterrorresponse()

    def getresponse(self, is_admin):
        self.context = {'has': []}
        for atr in dir(self):
            if isinstance(getattr(self, atr), Field):
                if not getattr(self, atr).isempty():
                    self.context['has'].append(atr)
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


class MethodRequest(PostRequest):
    account = CharField(required=False, nullable=True)
    login = CharField(required=True, nullable=True)
    token = CharField(required=True, nullable=True)
    arguments = ArgumentsField(required=True, nullable=True)
    method = CharField(required=True, nullable=False)

    methoddict = {
        'online_score': OnlineScoreRequest,
        'clients_interests': ClientsInterestsRequest
    }
    methodobj = None

    def __init__(self, request, ctx, store):
        super().__init__(request['body'], ctx, store)

    @property
    def is_admin(self):
        return self.login.value == ADMIN_LOGIN

    def getresponce(self):
        logging.info('Checking request fields validity.')
        if not self.isvalid():
            return self.geterrorresponse(), INVALID_REQUEST
        logging.info('Request fields validity.')

        logging.info('Checking authorization.')
        if not check_auth(self):
            return ERRORS[FORBIDDEN], FORBIDDEN
        logging.info('Authorization success.')

        logging.info('Checking method fields validity.')
        if not self.isvalid():
            return self.geterrorresponse(), INVALID_REQUEST

        # defining method
        if self.methoddict.get(self.method.value, None):
            self.methodobj = self.methoddict.get(
                    self.method.value)(self.arguments.value, self.store)
        else:
            return ERRORS['NOT_FOUND'], NOT_FOUND

        # checking method fields validity
        if not self.methodobj.isvalid():
            self.errorfields += self.methodobj.errorfields
            return self.geterrorresponse(), INVALID_REQUEST
        logging.info('Method fields are valid.')

        # updating context
        if self.methodobj:
            self.context.update(self.methodobj.context)

        return self.methodobj.getresponse(self.is_admin), OK


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
    logging.info("Producing validation.")
    mrequest = MethodRequest(request, ctx, store)
    return mrequest.getresponce()


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
            logging.info("%s: %s %s" % (
                self.path,
                request,
                context["request_id"]
            ))
            if path in self.router:
                try:
                    response, code = self.router[path](
                        {"body": request, "headers": self.headers},
                        context,
                        self.store
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
            r = {
                "error": response or ERRORS.get(code, "Unknown Error"),
                "code": code
            }
        context.update(r)
        logging.info(context)
        self.wfile.write(json.dumps(r).encode("ascii"))


if __name__ == "__main__":
    op = OptionParser()
    op.add_option("-p", "--port", action="store", type=int, default=8080)
    op.add_option("-l", "--log", action="store", default=None)
    (opts, args) = op.parse_args()
    logging.basicConfig(
        filename=opts.log,
        level=logging.INFO,
        format='[%(asctime)s] %(levelname).1s %(message)s',
        datefmt='%Y.%m.%d %H:%M:%S'
    )
    server = HTTPServer(("localhost", opts.port), MainHTTPHandler)
    logging.info("Starting server at %s" % opts.port)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    server.server_close()
