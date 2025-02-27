#!/usr/bin/env python3
import sys
import time
import socket
import struct
import xml.etree.ElementTree as ElementTree

UPNP_ORG_DEVICE_NS = 'urn:schemas-upnp-org:device-1-0'
UPNP_ORG_SERVICE_NS = 'urn:schemas-upnp-org:service-1-0'
UPNP_ORG_CONTROL_NS = 'urn:schemas-upnp-org:control-1-0'
# Used by Element.find()
UPNP_ORG_NS_MAP = {
    'device': UPNP_ORG_DEVICE_NS,
    'service': UPNP_ORG_SERVICE_NS,
    'control': UPNP_ORG_CONTROL_NS,
}

TR64_DEVICE_NS = 'urn:dslforum-org:device-1-0'
TR64_SERVICE_NS = 'urn:dslforum-org:service-1-0'
TR64_CONTROL_NS = 'urn:dslforum-org:control-1-0'
# Used by Element.find()
TR64_NS_MAP = {
    'device': TR64_DEVICE_NS,
    'service': TR64_SERVICE_NS,
    'control': TR64_CONTROL_NS,
}

#
# HTTP related code
#

HTTP_DEBUG = False

class HttpTransport(object):
    "Implements a base class for HTTP transport protocols"

    def __init__(self, type, proto, timeout=5):
        self.s = socket.socket(socket.AF_INET, type, proto)
        self.s.settimeout(timeout)
        self.timeout = timeout
    def __del__(self):
        if self.s:
            self.close()
    def is_multicast(self):
        return False
    def recv(self):
        return self.s.recvfrom(65536)
    def close(self):
        global HTTP_DEBUG
        if HTTP_DEBUG:
            print('Closing socket')
        self.s.close()
        self.s = None

class HttpTcpTransport(HttpTransport):
    "Implements HTTP over TCP"

    def __init__(self, remote_addr, timeout=5):
        global HTTP_DEBUG
        HttpTransport.__init__(self, socket.SOCK_STREAM, socket.IPPROTO_TCP, timeout)
        self.remote_addr = remote_addr
        self.timeout = timeout
        if HTTP_DEBUG:
            print('Connecting to %s:%d.' % remote_addr)
        self.s.connect(remote_addr)
    def send(self, data):
        self.s.send(data.encode())
    def recv(self):
        return (self.s.recv(65536), self.remote_addr)

class HttpUdpTransport(HttpTransport):
    "Implements HTTP over (unicast) UDP"

    def __init__(self, remote_addr, timeout=5):
        HttpTransport.__init__(self, socket.SOCK_DGRAM, socket.IPPROTO_UDP, timeout)
        self.remote_addr = remote_addr
        self.timeout = timeout
    def send(self, data):
        self.s.sendto(data.encode(), self.remote_addr)

class HttpUdpUnicastTransport(HttpUdpTransport):
    "Implements HTTP over unicast UDP"
    pass

class HttpUdpMulticastTransport(HttpUdpTransport):
    "Implements HTTP over multicast UDP"

    def __init__(self, remote_addr, bind_addr, mcast_ip, timeout=5):
        """Initialise the transport.
        
        remote_addr: remote endpoint address (as in socket address)
        bind_addr: local address to bind to (as in socket address)
        mcast_ip: multicast group IP address (typically same as in remote_addr)
        """
        HttpUdpTransport.__init__(self, remote_addr, timeout)
        #self.s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.s.bind(bind_addr)
        self.s.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 32)
        self.s.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_IF, socket.inet_aton(bind_addr[0]))
        mreq = socket.inet_aton(mcast_ip) + socket.inet_aton(bind_addr[0])
        self.s.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)
    def is_multicast(self):
        return True

def xlines(text):
    "Iterate over lines in text."

    index = 0
    while True:
        next_index = text.find("\n", index)
        if next_index == -1:
            raise StopIteration
        if text[next_index - 1] == "\r":
            line = text[index:next_index - 1]
        else:
            line = text[index:next_index]
        index = next_index + 1
        yield line

class HttpClient(object):
    """Implements a simple HTTP client via various transports.
    
    Currently not implemented:
    * Keep-alive connections
    
    Quirks:
    * Some HTTP servers don't respond at all when protocol is set to 1.0.
    """

    def __init__(self, transport, version='1.1'):
        self.http_version = version
        self._tr = transport

    def request(self, method, url, headers=None, body=None):
        """Perform a HTTP request.
        
        method: HTTP method to be sent in request line
        url: URL to be sent in request line
        headers: additional headers to be sent
        body: request body to be sent
        
        Returns:
        * Unicast transport: a tuple (status, headers, body)
        * Multicast transport: a list of tuples (addr, status, headers, body)
        """
        global HTTP_DEBUG
        
        request_lines = [ '%s %s HTTP/%s' % (method, url, self.http_version) ]
        has_host = False
        if headers:
            try:
                headers_items = headers.iteritems()
            except AttributeError:
                headers_items = headers.items()
            for header, value in headers_items:
                header = header.upper()
                has_host = has_host or header == 'HOST'
                request_lines.append('%s: %s' % (header, str(value)))
        if not has_host:
            request_lines.append('HOST: %s:%d' % self._tr.remote_addr)
        if body:
            request_lines.append('CONTENT-LENGTH: %d' % len(body))
        request_lines.append('\r\n')
        headers_text = '\r\n'.join(request_lines)
        if HTTP_DEBUG:
            print('Sending headers:')
            print(headers_text)
        self._tr.send(headers_text)
        if body:
            if HTTP_DEBUG:
                print('Sending body (%d bytes)' % len(body))
                print(body)
            self._tr.send(body)

        if self._tr.is_multicast():
            responses = []
            try:
                while True:
                    responses.append(self._do_recv(True))
            except socket.timeout:
                pass
            return responses
        else:
            response = self._do_recv()
            return (response[1], response[2], response[3])

    def _do_recv(self, pass_unkown = False):
        "Internal routine. Performs response reception."

        global HTTP_DEBUG
        
        response = ''
        end_of_headers = -1
        recv_start = time.time()
        while end_of_headers < 0:
            frag, addr = self._tr.recv()
            response += frag.decode('utf8')
            end_of_headers = response.find("\r\n\r\n")
            if end_of_headers < 0:
                end_of_headers = response.find("\n\n")
            if time.time() - recv_start > self._tr.timeout:
                raise socket.timeout
        body = response[end_of_headers + 4:]
        headers = response[:end_of_headers + 4]
        if HTTP_DEBUG:
            print('Received headers:')
            print(headers)
        status, headers = self._parse_headers(headers)
        
        if 'CONTENT-LENGTH' in headers:
            content_length = int(headers['CONTENT-LENGTH']) - len(body)
            recv_start = time.time()
            while content_length > 0:
                frag, addr = self._tr.recv()
                body += frag.decode('utf8')
                content_length -= len(frag)
                if time.time() - recv_start > self._tr.timeout:
                    raise socket.timeout
        elif 'TRANSFER-ENCODING' in headers and headers['TRANSFER-ENCODING'].lower() == 'chunked':
            buffer = body
            body = ''
            if HTTP_DEBUG:
                print('Starting chunked RX')
            while True:
                buffer_offset = 0
                while buffer.find("\n") == -1:
                    frag, addr = self._tr.recv()
                    buffer += frag.decode('utf8')
                buffer_offset = buffer.find("\n")
                if buffer_offset == 0:
                    buffer = buffer[1:]
                    continue
                elif buffer_offset == 1 and buffer[0] == "\r":
                    buffer = buffer[2:]
                    continue
                if HTTP_DEBUG:
                    print("Buffer offset: %d" % buffer_offset)
                if buffer[buffer_offset - 1] == "\r":
                    chunk_len = buffer[:buffer_offset - 1]
                else:
                    chunk_len = buffer[:buffer_offset]
                buffer_offset += 1
                if chunk_len == "0":
                    break
                chunk_len = int(chunk_len, 16)
                if HTTP_DEBUG:
                    print("Chunk length: %d" % chunk_len)
                    print("Buffer length: %d" % len(buffer))
                while len(buffer) - buffer_offset < chunk_len:
                    frag, addr = self._tr.recv()
                    buffer += frag.decode('utf8')
                body += buffer[buffer_offset:buffer_offset + chunk_len]
                buffer = buffer[buffer_offset + chunk_len:]
        elif pass_unkown:
            # Unknown transfer method
            pass
        else:
            end_of_body = -1
            recv_start = time.time()
            while end_of_body < 0:
                frag, addr = self._tr.recv()
                body += frag.decode('utf8')
                end_of_body = body.find("</root>")
                if time.time() - recv_start > self._tr.timeout:
                    break
            if end_of_body < 0:
                pass
        return (addr, status, headers, body)

    def _parse_headers(self, text):
        "Internal routine. Performs header parsing."

        lines = xlines(text)
        status = next(lines)
        headers = {}
        for line in lines:
            if len(line) == 0:
                break
            sep_index = line.find(':')
            if sep_index < 0:
                continue
            header = line[:sep_index].upper()
            sep_index += 1
            try:
                while line[sep_index] == ' ' or line[sep_index] == '\t':
                    sep_index += 1
                value = line[sep_index:]
            except:
                value = ''
            headers[header] = value
        return (status, headers)
# End of HttpClient

class URIParseError(Exception):
    pass

class URL(object):
    "Simple URL parser/combiner"

    def __init__(self, text):
        self.scheme = ''
        self.domain = ''
        self.port = 0
        self.path = ''
        self.query = ''
        self.frag = ''
        self.__parse(text)
    def __parse(self, text):
        offset = 0
        scheme_delim = text.find('://', offset)
        if scheme_delim >= 0:
            self.scheme = text[:scheme_delim]
            offset = scheme_delim + 3
        path_delim = text.find('/', offset)
        if path_delim < 0:
            raise URIParseError('URL format is incorrect (no path)')
        port_delim = text.find(':', offset, path_delim)
        if port_delim >= 0:
            self.domain = text[offset:port_delim]
            self.port = int(text[port_delim + 1:path_delim])
        else:
            self.domain = text[offset:path_delim]
        query_delim = text.find('?', path_delim)
        if query_delim >= 0:
            frag_delim = text.find('#', query_delim)
            if frag_delim >= 0:
                self.frag = text[frag_delim + 1:]
                self.query = text[query_delim + 1:frag_delim]
            else:
                self.query = text[query_delim + 1:]
            self.path = text[path_delim:query_delim]
        else:
            self.path = text[path_delim:]
    def __str__(self):
        text = ''
        if self.scheme:
            text += self.scheme + '://'
        text += self.domain
        if self.port:
            text += ':%d' % self.port
        text += self.path
        if self.query:
            text += '?' + self.query
        if self.frag:
            text += '#' + self.frag
        return text
# End of URL

class URN(object):
    "Simple URN parser/combiner"

    def __init__(self, text):
        self.nid = ''
        self.frags = []
        self.__parse(text)
    def __parse(self, text):
        if not text.startswith('urn:'):
            raise URIParseError('Text does not start with "urn:"')
        offset = 4
        sep_index = text.find(':', offset)
        self.nid = text[offset:sep_index]
        offset = sep_index + 1
        while True:
            sep_index = text.find(':', offset)
            if sep_index >= 0:
                self.frags.append(text[offset:sep_index])
                offset = sep_index + 1
            else:
                self.frags.append(text[offset:])
                break
    def __str__(self):
        text = 'urn:%s:' % self.nid
        text += ':'.join(self.frags)
        return text
# End of URN

def http_get(url, headers=None):
    "Shortcut for GETting a URL via HTTP/TCP"
    url = URL(url)
    port = url.port
    if not port:
        port = 80
    return HttpClient(HttpTcpTransport((url.domain, port))).request('GET', url.path, headers)

def http_post(url, headers=None, body=None):
    "Shortcut for POSTting to a URL via HTTP/TCP"
    url = URL(url)
    port = url.port
    if not port:
        port = 80
    return HttpClient(HttpTcpTransport((url.domain, port))).request('POST', url.path, headers, body)

#
# SSDP client code
#

class SsdpSearchResult(object):
    def __init__(self, ipaddr, headers):
        self.ipaddr = ipaddr
        self.server = headers.get('SERVER')
        self.location = headers.get('LOCATION')
        self.search_type = headers.get('ST')
        self.usn = headers.get('USN')
    def __str__(self):
        return 'SSDP search result:\r\n  IP: %s\r\n  Server: %s\r\n  Location: %s\r\n  USN: %s' % (self.ipaddr, self.server, self.location, self.usn)
    def __eq__(self, other):
        return self.ipaddr == other.ipaddr and self.usn == other.usn
    def __ne__(self, other):
        return not (self == other)

SSDP_MULTICAST_IPv4 = '239.255.255.250'
SSDP_PORT = 1900

def ssdp_search(transport, search_type):
    return HttpClient(transport).request('M-SEARCH', '*', {
            'HOST': '%s:%d' % (SSDP_MULTICAST_IPv4, SSDP_PORT),
            'ST': search_type,
            'MAN': '"ssdp:discover"',
            'MX': 1,
        })

def ssdp_search_uni(target_ip, search_type, timeout=5):
    "Perform a unicast SSDP M-SEARCH request"
    
    target_addr = (target_ip, SSDP_PORT)
    tr = HttpUdpUnicastTransport(target_addr, timeout)
    rsp = ssdp_search(tr, search_type)
    return SsdpSearchResult(target_ip, rsp[1])

def ssdp_search_multi(bind_addr, search_type, timeout=5):
    "Perform a multicast SSDP M-SEARCH request"
    
    tr = HttpUdpMulticastTransport(
        (SSDP_MULTICAST_IPv4, SSDP_PORT),
        bind_addr,
        SSDP_MULTICAST_IPv4,
        timeout)
    results = []
    for rsp in ssdp_search(tr, search_type):
        result = SsdpSearchResult(rsp[0][0], rsp[2])
        if result not in results:
            results.append(result)
    return results

#
# UPnP client code
#

UPNP_ACTIONS = False
UPNP_DEBUG = False

class UpnpError(Exception):
    pass

def clean_tag(tag):
    i = tag.find('}')
    if i < 0:
        return tag
    return tag[i+1:]

class UpnpServiceAction(object):
    "Describes a UPnP service action"

    def __init__(self):
        self.name = None
        self.args_in = []
        self.args_out = []
    
    def __str__(self):
        return '%s(%s)' % (self.name, ', '.join(self.args_in))
    __repr__ = __str__

    @staticmethod
    def from_xml(xml):
        o = UpnpServiceAction()
        for child in xml:
            tag = clean_tag(child.tag)
            if tag == 'name':
                o.name = child.text
            elif tag == 'argumentList':
                for arg_child in child:
                    arg_name, arg_dir = UpnpServiceAction._parse_arg(arg_child)
                    if arg_dir == 'in':
                        o.args_in.append(arg_name)
                    # Can't be bothered with args_out...
        return o

    @staticmethod
    def _parse_arg(xml):
        arg_name = None
        arg_dir = None
        for child in xml:
            tag = clean_tag(child.tag)
            if tag == 'name':
                arg_name = child.text
            elif tag == 'direction':
                arg_dir = child.text.lower()
        return (arg_name, arg_dir)
# End of UpnpServiceAction

class UpnpServiceDescriptor(object):
    "Dscribes service actions and state vars"

    def __init__(self):
        self.actions = {}
    
    def __str__(self):
        return "\r\n".join([str(a) for a in self.actions])
    __repr__ = __str__

    @staticmethod
    def from_xml(xml):
        #print('UpnpServiceDescriptor.from_xml()')
        o = UpnpServiceDescriptor()
        n = xml.find('service:actionList', UPNP_NS_MAP)
        if n is not None:
            for child in n:
                action = UpnpServiceAction.from_xml(child)
                o.actions[action.name] = action
        return o
# End of UpnpServiceDescriptor

class UpnpService(object):
    "Describes a UPnP service instance"

    def __init__(self, root):
        self._root = root
        # These describe the service type
        self.type = None
        self.type_urn = None
        self.scpd_url = None
        # These describe the service instance
        self.id = None
        self.control_url = None
        self.event_sub_url = None

    def __str__(self):
        return 'Service %s (type %s) %s' % (self.id, self.type, self.control_url)
    __repr__ = __str__

    @staticmethod
    def from_xml(xml, root):
        #print('UpnpService.from_xml()')
        o = UpnpService(root)
        for child in xml:
            tag = clean_tag(child.tag)
            if tag == 'serviceType' and not child.text is None:
                o.type_urn = URN(child.text)
                o.type = ':'.join(o.type_urn.frags[1:])
            elif tag == 'SCPDURL':
                o.scpd_url = child.text
            elif tag == 'serviceId' and not child.text is None:
                o.id = ':'.join(URN(child.text).frags[1:])
            elif tag == 'controlURL':
                o.control_url = child.text
            elif tag == 'eventSubURL':
                o.events_url = child.text
        return o

    def get_descriptor(self):
        try:
            return self._descriptor
        except:
            scpd_url = self.scpd_url
            if self._root.url_base is not None:
                if self._root.url_base.endswith('/') and scpd_url.startswith('/'):
                    scpd_url = scpd_url[1:]
                scpd_url = self._root.url_base + scpd_url
            sd = self._descriptor = self._root.get_scpd(self.type, scpd_url)
            return sd
        
    def invoke(self, action, **kwargs):
        sd = self.get_descriptor()
        
        # Don't bother with XML tools...
        try:
            kwargs_items = kwargs.iteritems()
        except AttributeError:
            kwargs_items = kwargs.items()
        args = ['<%s>%s</%s>' % (name, value, name) for name, value in kwargs_items]
        body_text = '<u:%s xmlns:u="%s">%s</u:%s>' % (action, self.type_urn, ''.join(args), action)
        xml = '<?xml version="1.0"?><s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/"><s:Body>'+body_text+'</s:Body></s:Envelope>'
        
        control_url = self.control_url
        if self._root.url_base is not None:
            control_url = self._root.url_base + control_url
        headers = {
                'SOAPACTION': '"%s#%s"' % (self.type_urn, action),
                'CONTENT-TYPE': 'text/xml; charset="utf-8"',
            }
        response_status, response_headers, response_body = http_post(control_url, headers, xml)
        # TODO: check HTTP status code
        xml = ElementTree.XML(response_body)
        xml = xml[0][0]
        root_tag = clean_tag(xml.tag)
        if root_tag == action + 'Response':
            args_out = {}
            for node in xml:
                tag = clean_tag(node.tag)
                args_out[tag] = node.text
            return args_out
        elif root_tag == 'Fault':
            raise UpnpError('Fault')
        else:
            raise UpnpError('Unknown tag')
# End of UpnpService

class UpnpDevice(object):
    "Describes a UPnP device"

    def __init__(self, root):
        self._root = root
        self.type = None
        self.type_urn = None
        self.name = None
        self.services = []
        self.subdevices = []

    def __str__(self):
        return 'Device %s (type %s)' % (self.name, self.type)
    __repr__ = __str__

    @staticmethod
    def from_xml(xml, root):
        #print('UpnpDevice.from_xml()')
        o = UpnpDevice(root)
        for child in xml:
            tag = clean_tag(child.tag)
            #print tag
            UpnpDevice._parse_node(o, tag, child)
        return o

    @staticmethod
    def _parse_node(o, tag, node):
        if tag == 'deviceType' and not node.text is None:
            o.type_urn = URN(node.text)
            o.type = ':'.join(o.type_urn.frags[1:])
        elif tag == 'friendlyName':
            o.name = node.text
        elif tag == 'serviceList':
            for child in node:
                o.services.append(UpnpService.from_xml(child, o._root))
        elif tag == 'deviceList':
            for child in node:
                o.subdevices.append(UpnpDevice.from_xml(child, o._root))
    
    def find_services(self, service_type, results=None):
        if results is None:
            results = []
        for s in self.services:
            if s.type == service_type:
                results.append(s)
        for d in self.subdevices:
            d.find_services(service_type, results)
        return results
# End of UpnpDevice

class UpnpRootDevice(UpnpDevice):
    "Describes a UPnP root device"

    def __init__(self, url_base=None):
        UpnpDevice.__init__(self, self)
        self.url_base = url_base
        self.service_types = {}

    def __str__(self):
        return 'Device %s (type %s)' % (self.name, self.type)
    __repr__ = __str__

    @staticmethod
    def from_xml(xml, url_base=None):
        #print('UpnpRootDevice.from_xml()')
        n = xml.find('device:URLBase', UPNP_NS_MAP)
        if n is not None:
            url_base = n.text
        n = xml.find('device:device', UPNP_NS_MAP)
        if n is None:
            raise Exception("no device node in device description")
        o = UpnpRootDevice(url_base)
        for child in n:
            tag = clean_tag(child.tag)
            UpnpRootDevice._parse_node(o, tag, child)
        return o
        
    @staticmethod
    def _parse_node(o, tag, node):
        if tag == 'manufacturer':
            o.manufacturer = node.text
        elif tag == 'modelName':
            o.model_name = node.text
        elif tag == 'modelDescription':
            o.model_description = node.text
        elif tag == 'modelNumber':
            o.model_number = node.text
        elif tag == 'UDN':
            o.udn = node.text
        elif tag == 'UPC':
            o.upc = node.text
        elif tag == 'presentationURL':
            o.presentation_url = node.text
        else:
            UpnpDevice._parse_node(o, tag, node)
    
    def get_scpd(self, service_type, scpd_url):
        try:
            return self.service_types[service_type]
        except KeyError:
            pass
        if UPNP_DEBUG:
            print('Getting SCPD')
        desc_text = http_get(scpd_url)[2]
        desc_xml = ElementTree.XML(desc_text)
        sd = UpnpServiceDescriptor.from_xml(desc_xml)
        self.service_types[service_type] = sd
        return sd
# End of UpnpRootDevice

def upnp_print_schema(root, indent=''):
    print('%s%s' % (indent, root))
    indent += '  '
    for s in root.services:
        print('%s%s' % (indent, s))
        if UPNP_ACTIONS:
            sd = s.get_descriptor()
            try:
                sd_actions_items = sd.actions.iteritems()
            except AttributeError:
                sd_actions_items = sd.actions.items()
            for an, a in sd_actions_items:
                print('%s->%s' % (indent, a))
    for d in root.subdevices:
        upnp_print_schema(d, indent)

def upnp_get_service(root, type):
    for s in root.services:
        if s.type != type:
            continue
        return s
    for d in root.subdevices:
        s = upnp_get_service(d, type)
        if s is not None:
            return s
    return None

def upnp_process_description(location):
    if UPNP_DEBUG:
        print('Getting description...')
    desc = http_get(location)
    desc_xml = ElementTree.XML(desc[2])
    # NOTE: Some device descriptors don't contain URL base.
    # Use location as base, then.
    base_url = URL(location)
    base_url.path = ''
    return UpnpRootDevice.from_xml(desc_xml, str(base_url))

def discovery_channel(bind_addr):
    print('Searching for root devices...')
    ssdp_results = ssdp_search_multi(bind_addr, 'upnp:rootdevice', timeout=3)
    if not ssdp_results:
        print('No devices found!')
        return

    devices = {}
    for ssdp_result in ssdp_results:
        print(ssdp_result)
        retry_location = ''
        try:
            device = upnp_process_description(ssdp_result.location)
            upnp_print_schema(device)
        except:
            print('could not get device description')
            if ssdp_result.ipaddr not in ssdp_result.location:
                retry_location = ssdp_result.location
        if retry_location != '':
            retry_location = retry_location.split(':')
            if len(retry_location) > 2:
                retry_location[1] = '//'+ssdp_result.ipaddr
                retry_location = ':'.join(retry_location)
            else:
                retry_location = ''
        if retry_location != '':
            print('  Location: %s' % (retry_location))
            try:
                device = upnp_process_description(retry_location)
                upnp_print_schema(device)
            except:
                print('could not get device description')
        #s = device.find_services('WANIPConnection:1')
        #r = s[0].invoke('GetExternalIPAddress')

def set_upnp_ns(on):
    global UPNP_NS_MAP
    global UPNP_DEVICE_NS
    global UPNP_SERVICE_NS
    global UPNP_CONTROL_NS
    if on:
        UPNP_NS_MAP = UPNP_ORG_NS_MAP
    else:
        UPNP_NS_MAP = TR64_NS_MAP
    UPNP_DEVICE_NS = UPNP_NS_MAP['device']
    UPNP_SERVICE_NS = UPNP_NS_MAP['service']
    UPNP_CONTROL_NS = UPNP_NS_MAP['control']
    # Used by writer
    ElementTree.register_namespace('soap', 'http://schemas.xmlsoap.org/soap/envelope/')
    ElementTree.register_namespace('device', UPNP_DEVICE_NS)
    ElementTree.register_namespace('service', UPNP_SERVICE_NS)
    ElementTree.register_namespace('control', UPNP_CONTROL_NS)

def set_upnp_actions(on):
    global UPNP_ACTIONS
    UPNP_ACTIONS = on

set_upnp_ns(1)
