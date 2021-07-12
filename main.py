#!/usr/bin/env python3

import socket
import mimetypes
import json
import os
import multiprocessing
import re
import logging
import selectors
from datetime import datetime
from http import HTTPStatus
import traceback


def load_httpd_settings():
    with open("settings.json", "r") as file:
        settings = json.load(file)
        for unused, values in settings.items():
            for key, value in values.items():
                os.environ[key] = str(value)

def make_logger():
    logger = logging.getLogger("python_http_server")
    logger.setLevel(logging.DEBUG)

    formatter = logging.Formatter("%(asctime)s - %(levelname)s - %(message)s")

    console_handler = logging.StreamHandler()
    console_handler.setLevel(logging.DEBUG)
    console_handler.setFormatter(formatter)

    if "LOG_FOLDER" in os.environ:
        if os.path.exists(os.environ["LOG_FOLDER"]) == False and os.path.isdir(os.environ["LOG_FOLDER"]) == False:
            os.mkdir(os.environ["LOG_FOLDER"])
        file_handler = logging.FileHandler(os.environ["LOG_FOLDER"] + "/{}.log".format(str(datetime.now()).replace("-", "_").replace(" ", "_").replace(":", "_").replace(".", "_")))
        file_handler.setLevel(logging.DEBUG)
        file_handler.setFormatter(formatter)
    
    logger.addHandler(console_handler)
    logger.addHandler(file_handler)

    logger.info("Logger made!")

    return logger

class client_handler:

    parent_conn = ""

    client_socket = 0
    client_address = ()

    settings = []
    host_finding_regex = r"(?:Host: (?P<request_host>[a-zA-Z-_.]+)(?::(?P<request_port>[\d]+))?)"

    made_response = False

    http_request = ""
    http_response = bytes()

    request_headers = {}
    request_body = ""

    response_headers = ""
    response_body = ""

    def __init__(self, client_socket, client_address, settings, parent_conn):
        self.settings = settings
        self.client_socket = client_socket
        self.client_address = client_address
        self.parent_conn = parent_conn

        try:
            self.parent_conn.send("info:client handler process: {} is starting".format(os.getpid()))

            self.client_socket.settimeout(int(os.environ["DEFAULT_TIMEOUT_TIME"]))

            self.http_request = self.recv_all().decode()

            try:
                self.handle_http_request()
                self.parent_conn.send("info:client handler process: {} is shuting down".format(os.getpid()))
            except:
                self.parent_conn.send("info:client handler process: {} is shuting down".format(os.getpid()))

        except socket.timeout:
            self.parent_conn.send("info:Process {} timeout".format(os.getpid()))
        except ConnectionAbortedError:
            self.parent_conn.send("info:Process {} closed connection".format( os.getpid()))
        except ConnectionResetError:
            self.parent_conn.send("info:Client process {} closed connection".format(os.getpid()))
        except Exception:
            self.parent_conn.send("warning:General error at process {}".format(os.getpid()))
            error = traceback.format_exc()
            self.parent_conn.send("warning:{}".format(error))

    def handle_http_request(self):
        self.client_socket.settimeout(int(os.environ["DEFAULT_TIMEOUT_TIME"]))

        try:
            while True:
                if self.http_request == None:
                    self.http_request = self.recv_all().decode()

                self.parent_conn.send("info:Got request from {}:{}, client process with id of: {}".format(
                    self.client_address[0], self.client_address[1], os.getpid()
                ))

                match_host = re.search(self.host_finding_regex, self.http_request)

                self.prase_requset()

                for site in self.settings:
                    for domain in site[0][0]:
                        if match_host == None:
                            break
                        if match_host.group("request_host") == domain:
                            self.make_response(site)
                            self.made_response = True
                            break
                    if self.made_response == True:
                        break

                if self.made_response == False or self.http_response == bytes():
                    self.handle_404()

                self.send_response()

                self.http_request = None
                self.response_body = ""
                self.response_headers = ""
                self.http_response = bytes()
                self.made_response = False

        except socket.timeout:
            self.parent_conn.send("info:Process {} timeout".format(os.getpid()))
        except ConnectionAbortedError:
            self.parent_conn.send("info:Process {} closed connection".format( os.getpid()))
        except ConnectionResetError:
            self.parent_conn.send("info:Client process {} closed connection".format(os.getpid()))
        except Exception:
            self.parent_conn.send("warning:General error at process {}".format(os.getpid()))
            error = traceback.format_exc()
            self.parent_conn.send("warning:{}".format(error))

        self.parent_conn.send("info:Client process {} handled, exiting".format(os.getpid()))

    def prase_requset(self):
        try:
            temp_holder_for_headers, self.request_body = self.http_request.split("\r\n\r\n", 1)
        except:
            temp_holder_for_headers = self.http_request

        temp_holder_for_headers = temp_holder_for_headers.split("\r\n")

        first_header = temp_holder_for_headers[0].split(" ")

        temp_holder_for_headers.pop(0)

        if first_header[0] == "":
            self.handle_404()
            self.made_response = True
            return None

        self.request_headers["Method"] = first_header[0]
        self.request_headers["Path"] = first_header[1]
        self.request_headers["Http-Version"] = first_header[2]

        for header in temp_holder_for_headers:
            header = header.split(": ")
            self.request_headers[header[0]] = header[1]
        
        if self.request_headers["Method"] == "GET":
            if "?" in self.request_headers["Path"]:
                self.request_headers["Path"], self.request_headers["Query"] = self.request_headers["Path"].split("?", 1)
        elif self.request_headers["Method"] == "POST":
            self.request_headers["Query"] = self.request_body
            self.request_body = ""

        if "Content-Length" in self.request_headers:
            self.request_body = self.request_body[:self.request_headers["Content-Length"]]
        else:
            self.response_body = ""

    def handle_404(self):
        self.response_body = "{} {}".format(HTTPStatus.NOT_FOUND.value, HTTPStatus.NOT_FOUND.description)
        self.response_headers = "{} {} {}\r\n".format(self.request_headers["Http-Version"], HTTPStatus.NOT_FOUND.value, HTTPStatus.NOT_FOUND.phrase)
        self.response_headers += "Content-Type: text/plain\r\n"
        self.response_headers += "Content-Length: {}\r\n".format(len(self.response_body))
        self.response_headers += "\r\n"
        self.http_response = self.response_headers.encode() + self.response_body.encode()

    def handle_static_file(self, path, requested_file):
        file_path = path + requested_file
        if os.path.exists(file_path) and os.path.isfile(file_path):
            with open(file_path, "rb") as file_to_read:
                self.response_body = file_to_read.read()
                self.response_headers = "{} {} {}\r\n".format(self.request_headers["Http-Version"], HTTPStatus.OK.value, HTTPStatus.OK.phrase)
                self.response_headers += "Content-Type: {}\r\n".format(mimetypes.guess_type(file_path)[0] if mimetypes.guess_type(file_path)[0] != None else "application/octet-stream")
                self.response_headers += "Content-Length: {}\r\n".format(len(self.response_body))
                self.response_headers += "\r\n"
                self.http_response = self.response_headers.encode() + self.response_body
                return True
        return False

    def make_response(self, site):
        if ".." in self.request_headers["Path"]:
            self.response_body = "{} {}".format(HTTPStatus.BAD_REQUEST.value, HTTPStatus.BAD_REQUEST.description)
            self.response_headers = "{} {} {}\r\n".format(self.request_headers["Http-Version"], HTTPStatus.BAD_REQUEST.value, HTTPStatus.BAD_REQUEST.phrase)
            self.response_headers += "Content-Type: text/plain\r\n"
            self.response_headers += "Content-Length: {}\r\n".format(len(self.response_body))
            self.response_headers += "\r\n"
            self.http_response = self.response_headers.encode() + self.response_body.encode()
            return None

        if self.request_headers["Path"] == "/" :
            if self.handle_static_file(site[0][1]["document_root"], "/index.html") == True:
                return None

        if len(self.request_headers["Path"].rsplit(".", 1)) == 2:
            if self.handle_static_file(site[0][1]["document_root"], self.request_headers["Path"].replace("static/", "")) == True:
                return None

        if "static_root" in site[0][1]:
            for static_url_path in site[0][1]["static_root"]:
                if self.request_headers["Path"].startswith("/static/"):
                    if self.handle_static_file(site[0][1]["static_root"][static_url_path], self.request_headers["Path"].replace("static/", "")) == True:
                        return None

        self.handle_404()
        
    def send_response(self):
        if self.http_response != None:
            size = len(self.http_response)
            size_sent = self.client_socket.send(self.http_response)
            if size == size_sent:
                self.parent_conn.send("info:Sent response to {}:{}, {} sent, client process with id of: {}".format(
                    self.client_address[0], self.client_address[1], size_sent, os.getpid()
                ))
            else:
                self.parent_conn.send("warning:Error sending response, only {} sent from total of {}, client process if of: {}".format(size_sent, size, os.getpid()))
        else:
            self.parent_conn.send("warning:Error sending response, noting to send, client procces id of: {}".format(os.getpid()))

    def prepare_cgi_request(self):
        pass

    def recv_all(self):
        buffer_size = int(os.environ["DEFAULT_SOCKET_BUFFER_SIZE"])
        data = bytes()
        while True:
            packet = self.client_socket.recv(buffer_size)
            data += packet
            if len(packet) < buffer_size:
                break
        return data

class server_hadler:
    
    listening_domains = []
    listen_port = 0
    listen_ip = ""
    settings = {}
    parent_conn = ""

    def __init__(self, ip, port, settings, parent_conn):
        self.listen_port = port
        self.settings = settings
        self.parent_conn = parent_conn

        if ip == "*":
            self.listening_domains.append("0.0.0.0")
            self.listen_ip = "0.0.0.0"
            address = ("0.0.0.0", int(self.listen_port))
        elif ip == "127.0.0.1" or ip == "localhost":
            self.listening_domains.append("localhost")
            self.listen_ip = "localhost"
            address = ("localhost", int(self.listen_port))
        else:
            self.listening_domains.append(ip)
            self.listen_ip = "0.0.0.0"
            address = ("0.0.0.0", int(self.listen_port))

        parent_conn.send("info:New server process with id of: {}, listening to {}:{}".format(os.getpid(), address[0], address[1]))

        server_socket = socket.socket(family=socket.AF_INET, type=socket.SOCK_STREAM)
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_socket.bind(address)
        server_socket.listen(int(os.environ["DEFAULT_CLIENT_LISTEN_AMOUNT"]))

        while True:
            client_socket, client_address = server_socket.accept()
            client_process = multiprocessing.Process(target=client_handler, args=(client_socket, client_address, self.settings, self.parent_conn))
            client_process.start()

def spwan_processes(logger):
    BASE_PATH_SERVER = os.path.abspath(os.path.dirname(__file__)) + "/"
    SITES_FOLDER = os.path.join(BASE_PATH_SERVER, "sites/")

    processes = {}

    site_settings = {}

    if os.path.exists(os.path.join(BASE_PATH_SERVER, "sites/")) and os.path.isdir(os.path.join(BASE_PATH_SERVER, "sites/")):
        for site_config_path in os.scandir(SITES_FOLDER):
            settings = json.load(open(site_config_path))

            listen_address = next(iter(settings.keys()))

            listen_ip, listen_port = listen_address.split(":")

            site_setting = list()

            domians = (settings[listen_address]["site_name"], ) + tuple(settings[listen_address]["site_alias"] if "site_alias" in settings[listen_address] else tuple())

            settings[listen_address].pop("site_name")
            settings[listen_address].pop("site_alias") if "site_alias" in settings[listen_address] else None

            site_setting.append((
                domians,
                settings[listen_address]
            ))

            if listen_ip == "*":
                key = "{}:{}".format("0.0.0.0", listen_port)
            elif listen_ip == "127.0.0.1" or listen_ip == "localhost":
                key = "{}:{}".format("localhost", listen_port)

            if key in site_settings:
                site_settings[key].append(site_setting)
            else:
                site_settings[key] = [site_setting]

    parent_conn, child_conn = multiprocessing.Pipe()

    for settings in site_settings.keys():
        processes[key] = multiprocessing.Process(target=server_hadler, name=key, args=(listen_ip, listen_port, site_settings[settings], child_conn))
        processes[key].start()

    logger.info("Spawned server procceses!")

    return parent_conn

def write_to_log(logger, message):
    log_type, message = message.split(":", 1)

    if log_type == "info":
        logger.info(message)
    elif log_type == "warning":
        logger.warning(message)

def main():
    load_httpd_settings()
    logger = make_logger()
    parent_conn = spwan_processes(logger)

    while True:
        message = parent_conn.recv()
        write_to_log(logger, message)

if __name__ == "__main__":
    main()

# https://tools.ietf.org/html/rfc6265
# https://tools.ietf.org/html/rfc7230
# https://tools.ietf.org/html/rfc7231
# https://tools.ietf.org/html/rfc7232
# https://tools.ietf.org/html/rfc7233
# https://tools.ietf.org/html/rfc7233
# https://tools.ietf.org/html/rfc7234
# https://tools.ietf.org/html/rfc7235
# https://tools.ietf.org/html/rfc7725

# https://tools.ietf.org/html/rfc3875

# https://www.iana.org/assignments/media-types/media-types.xhtml