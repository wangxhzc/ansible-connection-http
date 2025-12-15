from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

DOCUMENTATION = """
    author: Your Name
    name: http
    short_description: Run tasks via HTTP(S) agent
    description:
        - Use HTTP(S) to connect to targets via an agent
        - Requires an agent running on the target that exposes an HTTP(S) interface
        - Supports both HTTP and HTTPS protocols
    version_added: "1.0"
    options:
      remote_addr:
        description:
            - Address of the remote target
        default: inventory_hostname
        vars:
            - name: inventory_hostname
            - name: ansible_host
            - name: ansible_http_host
      remote_user:
        description:
            - User for authentication
        vars:
            - name: ansible_user
            - name: ansible_http_user
        ini:
            - section: defaults
              key: remote_user
            - section: http_connection
              key: remote_user
        keyword:
            - name: remote_user
      password:
        description:
          - Password for authentication
        vars:
            - name: ansible_password
            - name: ansible_http_pass
      agent_port:
        description:
            - Port on which the agent is listening
        default: 18443
        ini:
            - section: http_connection
              key: agent_port
        env:
            - name: ANSIBLE_HTTP_AGENT_PORT
        vars:
            - name: ansible_http_agent_port
      agent_scheme:
        description:
            - HTTP scheme to use (http or https)
        default: https
        choices: [http, https]
        ini:
            - section: http_connection
              key: agent_scheme
        env:
            - name: ANSIBLE_HTTP_AGENT_SCHEME
        vars:
            - name: ansible_http_agent_scheme
      agent_uri:
        description:
            - Base URI for the agent API
        default: /api/v1
        ini:
            - section: http_connection
              key: agent_uri
        env:
            - name: ANSIBLE_HTTP_AGENT_URI
        vars:
            - name: ansible_http_agent_uri
      verify_ssl:
        description:
            - Verify SSL certificate validity
        default: True
        type: boolean
        ini:
            - section: http_connection
              key: verify_ssl
        env:
            - name: ANSIBLE_HTTP_VERIFY_SSL
        vars:
            - name: ansible_http_verify_ssl
"""

import os
import json
import urllib.request
import urllib.parse
import urllib.error
import base64
import sys
from ansible.errors import (
    AnsibleConnectionFailure,
    AnsibleAuthenticationFailure,
    AnsibleError
)
from ansible.plugins.connection import ConnectionBase
from ansible.utils.display import Display

display = Display()


class Connection(ConnectionBase):
    ''' HTTP(S) connection to agent running on target '''

    transport = 'http'

    def __init__(self, *args, **kwargs):
        super(Connection, self).__init__(*args, **kwargs)
        self.url = None
        self._connected = False
        self.session = None

    def _connect(self, port=None):
        super(Connection, self)._connect()

        if not self._connected:
            self._connected = True

    def _get_url(self):
        '''
        Build the URL for the agent endpoint
        '''
        host = self.get_option('remote_addr') or self._play_context.remote_addr
        port = self.get_option('agent_port')
        scheme = self.get_option('agent_scheme')
        uri = self.get_option('agent_uri')
        
        return "{scheme}://{host}:{port}{uri}".format(
            scheme=scheme,
            host=host,
            port=port,
            uri=uri
        )

    def _build_request(self, method, path, data=None, headers=None):
        '''
        Build an HTTP request
        '''
        if not self.session:
            self.session = urllib.request.build_opener()
            
            # Set default headers
            self.session.addheaders = [('User-agent', 'Ansible-http-connection')]
            
            # Handle authentication
            user = self.get_option('remote_user') or self._play_context.remote_user
            password = self.get_option('password') or self._play_context.password
            
            if user and password:
                credentials = '{0}:{1}'.format(user, password)
                encoded_credentials = base64.b64encode(credentials.encode('utf-8')).decode('ascii')
                self.session.addheaders.append(('Authorization', 'Basic ' + encoded_credentials))

        url = self._get_url() + path
        
        if not headers:
            headers = {}
            
        if data and isinstance(data, dict):
            data = json.dumps(data).encode('utf-8')
            headers['Content-Type'] = 'application/json'
            
        request = urllib.request.Request(url, data=data, headers=headers)
        request.get_method = lambda: method
        
        return request

    def _make_request(self, method, path, data=None, headers=None):
        '''
        Make an HTTP request and handle the response
        '''
        request = self._build_request(method, path, data, headers)
        
        # SSL verification setting
        verify_ssl = self.get_option('verify_ssl')
        if not verify_ssl:
            # Create a custom HTTPS handler that doesn't verify SSL certs
            import ssl
            
            # First try the modern approach
            try:
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                https_handler = urllib.request.HTTPSHandler(context=ctx)
            except (AttributeError, TypeError):
                # Fallback for older Python versions
                # Create an unverified HTTPS context
                try:
                    # Python 2.7.9+ but < 2.7.14
                    ctx = ssl._create_unverified_context()
                    https_handler = urllib.request.HTTPSHandler(context=ctx)
                except AttributeError:
                    # Even older Python, just disable certificate verification globally
                    if hasattr(ssl, '_create_unverified_context'):
                        ssl._create_default_https_context = ssl._create_unverified_context
                    https_handler = urllib.request.HTTPSHandler()
            
            # Build a new opener with the custom HTTPS handler
            opener = urllib.request.build_opener(https_handler)
            
            # Copy headers from the original session
            if self.session:
                opener.addheaders = self.session.addheaders
            
            return opener.open(request)
        else:
            return self.session.open(request)

    def exec_command(self, cmd, in_data=None, sudoable=True):
        '''
        Run a command on the remote host via the agent
        '''
        super(Connection, self).exec_command(cmd, in_data=in_data, sudoable=sudoable)

        display.vvv("EXEC {0}".format(cmd), host=self._play_context.remote_addr)

        try:
            payload = {
                'command': cmd,
                'in_data': in_data
            }
            
            response = self._make_request('POST', '/execute', data=payload)
            result = json.loads(response.read().decode('utf-8'))
            
            return (result['rc'], result['stdout'], result['stderr'])
        except urllib.error.HTTPError as e:
            errmsg = e.read().decode('utf-8')
            raise AnsibleConnectionFailure("HTTP error {0}: {1}".format(e.code, errmsg))
        except urllib.error.URLError as e:
            raise AnsibleConnectionFailure("URL error: {0}".format(str(e)))
        except Exception as e:
            raise AnsibleConnectionFailure("Unexpected error: {0}".format(str(e)))

    def put_file(self, in_path, out_path):
        '''
        Transfer a file from local to remote via the agent
        '''
        super(Connection, self).put_file(in_path, out_path)
        
        display.vvv("PUT {0} TO {1}".format(in_path, out_path), 
                   host=self._play_context.remote_addr)

        try:
            if not os.path.exists(in_path):
                raise AnsibleError("Local file {0} does not exist".format(in_path))
                
            with open(in_path, 'rb') as f:
                file_content = base64.b64encode(f.read()).decode('utf-8')
                
            payload = {
                'dest': out_path,
                'content': file_content,
                'mode': '0644'
            }
            
            response = self._make_request('POST', '/put_file', data=payload)
            result = json.loads(response.read().decode('utf-8'))
            
            if not result.get('success', False):
                raise AnsibleConnectionFailure("Failed to put file: {0}".format(result.get('msg')))
                
        except urllib.error.HTTPError as e:
            errmsg = e.read().decode('utf-8')
            raise AnsibleConnectionFailure("HTTP error {0}: {1}".format(e.code, errmsg))
        except urllib.error.URLError as e:
            raise AnsibleConnectionFailure("URL error: {0}".format(str(e)))

    def fetch_file(self, in_path, out_path):
        '''
        Fetch a file from remote to local via the agent
        '''
        super(Connection, self).fetch_file(in_path, out_path)
        
        display.vvv("FETCH {0} TO {1}".format(in_path, out_path),
                   host=self._play_context.remote_addr)

        try:
            payload = {
                'src': in_path
            }
            
            response = self._make_request('POST', '/fetch_file', data=payload)
            result = json.loads(response.read().decode('utf-8'))
            
            if not result.get('success', False):
                raise AnsibleConnectionFailure("Failed to fetch file: {0}".format(result.get('msg')))
            
            # Decode and write file content
            file_content = base64.b64decode(result['content'])
            with open(out_path, 'wb') as f:
                f.write(file_content)
                
        except urllib.error.HTTPError as e:
            errmsg = e.read().decode('utf-8')
            raise AnsibleConnectionFailure("HTTP error {0}: {1}".format(e.code, errmsg))
        except urllib.error.URLError as e:
            raise AnsibleConnectionFailure("URL error: {0}".format(str(e)))

    def close(self):
        '''
        Close the connection
        '''
        self._connected = False

    def reset(self):
        '''
        Reset the connection
        '''
        self.close()
        self._connect()