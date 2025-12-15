#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Copyright 2025 wangxhzc
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# AGENT_LOG_LEVEL=ERROR
# AGENT_LOG_LEVEL=INFO
# AGENT_LOG_LEVEL=DEBUG

"""
实现Ansible HTTP连接插件所需的三个接口:
1. /api/v1/execute - 执行命令
2. /api/v1/put_file - 上传文件
3. /api/v1/fetch_file - 下载文件
"""

import http.server
import json
import subprocess
import base64
import os
import sys
import ssl
import logging
from urllib.parse import urlparse


class AgentHTTPRequestHandler(http.server.BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        """
        重写日志方法，使用标准日志记录器
        """
        logger = logging.getLogger('ansible_agent')
        logger.info("%s - - [%s] %s" % (
            self.address_string(),
            self.log_date_time_string(),
            format % args
        ))
    
    def do_POST(self):
        # 获取日志记录器
        logger = logging.getLogger('ansible_agent')
        
        # 解析请求路径
        parsed_path = urlparse(self.path)
        
        # 获取请求内容长度
        content_length = int(self.headers.get('Content-Length', 0))
        post_data = self.rfile.read(content_length)
        
        try:
            # 解析JSON数据
            if content_length > 0:
                data = json.loads(post_data.decode('utf-8'))
            else:
                data = {}
        except json.JSONDecodeError as e:
            logger.error(f"Invalid JSON data from {self.client_address[0]}: {e}")
            self.send_error(400, "Invalid JSON data")
            return
        
        # 记录调试信息
        logger.debug(f"Received POST request from {self.client_address[0]}: {self.path} with data: {data}")
        
        # 根据路径处理不同请求
        if parsed_path.path == '/api/v1/execute':
            self.handle_execute(data)
        elif parsed_path.path == '/api/v1/put_file':
            self.handle_put_file(data)
        elif parsed_path.path == '/api/v1/fetch_file':
            self.handle_fetch_file(data)
        else:
            logger.info(f"Unknown endpoint requested by {self.client_address[0]}: {parsed_path.path}")
            self.send_error(404, "Not Found")
    
    def handle_execute(self, data):
        """
        处理命令执行请求
        """
        logger = logging.getLogger('ansible_agent')
        command = data.get('command')
        
        if not command:
            logger.warning(f"Missing command parameter from {self.client_address[0]}")
            self.send_error(400, "Missing command parameter")
            return
        
        logger.info(f"Executing command for {self.client_address[0]}: {command}")
        
        try:
            # 执行命令
            result = subprocess.run(
                command, 
                shell=True, 
                stdout=subprocess.PIPE, 
                stderr=subprocess.PIPE,
                text=True,
                timeout=300  # 5分钟超时
            )
            
            # 准备响应数据
            response_data = {
                'rc': result.returncode,
                'stdout': result.stdout,
                'stderr': result.stderr
            }
            
            # 记录调试信息
            logger.debug(f"Command response for {self.client_address[0]}: {response_data}")
            
            # 发送响应
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps(response_data).encode('utf-8'))
            
        except subprocess.TimeoutExpired:
            logger.error(f"Command timeout for {self.client_address[0]}: {command}")
            self.send_error(500, "Command execution timeout")
        except Exception as e:
            logger.error(f"Error executing command for {self.client_address[0]}: {str(e)}")
            self.send_error(500, f"Error executing command: {str(e)}")
    
    def handle_put_file(self, data):
        """
        处理文件上传请求
        """
        logger = logging.getLogger('ansible_agent')
        dest = data.get('dest')
        content = data.get('content')
        
        if not dest:
            logger.warning(f"Missing dest parameter from {self.client_address[0]}")
            self.send_error(400, "Missing dest parameter")
            return
            
        if content is None:
            logger.warning(f"Missing content parameter from {self.client_address[0]}")
            self.send_error(400, "Missing content parameter")
            return
        
        logger.info(f"Writing file for {self.client_address[0]}: {dest}")
        
        try:
            # 创建目录（如果不存在）
            dest_dir = os.path.dirname(dest)
            if dest_dir and not os.path.exists(dest_dir):
                os.makedirs(dest_dir, exist_ok=True)
            
            # 解码并写入文件
            file_content = base64.b64decode(content)
            with open(dest, 'wb') as f:
                f.write(file_content)
            
            # 发送响应
            response_data = {
                'success': True,
                'msg': f"File written to {dest}"
            }
            
            # 记录调试信息
            logger.debug(f"Put file response for {self.client_address[0]}: {response_data}")
            
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps(response_data).encode('utf-8'))
            
        except Exception as e:
            response_data = {
                'success': False,
                'msg': f"Error writing file: {str(e)}"
            }
            logger.error(f"Error writing file {dest} for {self.client_address[0]}: {str(e)}")
            self.send_response(500)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps(response_data).encode('utf-8'))
    
    def handle_fetch_file(self, data):
        """
        处理文件下载请求
        """
        logger = logging.getLogger('ansible_agent')
        src = data.get('src')
        
        if not src:
            logger.warning(f"Missing src parameter from {self.client_address[0]}")
            self.send_error(400, "Missing src parameter")
            return
        
        logger.info(f"Reading file for {self.client_address[0]}: {src}")
        
        try:
            # 检查文件是否存在
            if not os.path.exists(src):
                response_data = {
                    'success': False,
                    'msg': f"File not found: {src}"
                }
                logger.debug(f"Fetch file response for {self.client_address[0]}: {response_data}")
                self.send_response(404)
                self.send_header('Content-Type', 'application/json')
                self.end_headers()
                self.wfile.write(json.dumps(response_data).encode('utf-8'))
                return
            
            # 读取并编码文件内容
            with open(src, 'rb') as f:
                file_content = base64.b64encode(f.read()).decode('utf-8')
            
            # 发送响应
            response_data = {
                'success': True,
                'content': file_content
            }
            
            # 记录调试信息
            logger.debug(f"Fetch file response for {self.client_address[0]}: success")
            
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps(response_data).encode('utf-8'))
            
        except Exception as e:
            response_data = {
                'success': False,
                'msg': f"Error reading file: {str(e)}"
            }
            logger.error(f"Error reading file {src} for {self.client_address[0]}: {str(e)}")
            self.send_response(500)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps(response_data).encode('utf-8'))
    
    def do_GET(self):
        """
        处理GET请求，用于健康检查
        """
        logger = logging.getLogger('ansible_agent')
        logger.info(f"Health check request from {self.client_address[0]}")
        
        self.send_response(200)
        self.send_header('Content-Type', 'text/plain')
        self.end_headers()
        self.wfile.write(b"Ansible HTTP Agent is running")


def main():
    # 默认参数
    port = 18443
    certfile = None
    keyfile = None
    
    # 解析命令行参数
    args = sys.argv[1:]
    while args:
        arg = args.pop(0)
        if arg == '--port' and args:
            try:
                port = int(args.pop(0))
            except ValueError:
                print("Invalid port number")
                sys.exit(1)
        elif arg == '--cert' and args:
            certfile = args.pop(0)
        elif arg == '--key' and args:
            keyfile = args.pop(0)
        else:
            print("Usage: agent_example.py [--port PORT] [--cert CERTFILE] [--key KEYFILE]")
            print("Example: agent_example.py --port 18443 --cert server.crt --key server.key")
            sys.exit(1)
    
    # 设置日志记录器
    logger = logging.getLogger('ansible_agent')
    
    # 从环境变量获取日志级别，默认为INFO
    log_level = os.environ.get('AGENT_LOG_LEVEL', 'INFO').upper()
    if log_level == 'DEBUG':
        logger.setLevel(logging.DEBUG)
    elif log_level == 'ERROR':
        logger.setLevel(logging.ERROR)
    else:
        logger.setLevel(logging.INFO)
    
    # 控制台处理器
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(logging.DEBUG)  # 处理器级别设为DEBUG，由logger控制实际输出级别
    
    # 创建格式化器
    formatter = logging.Formatter(
        '%(asctime)s - %(levelname)s - %(message)s'
    )
    console_handler.setFormatter(formatter)
    logger.addHandler(console_handler)
    
    logger.info(f"Starting Ansible HTTP Agent with log level: {log_level}")
    
    # 创建服务器
    server_address = ('', port)
    httpd = http.server.HTTPServer(server_address, AgentHTTPRequestHandler)
    
    # 配置SSL
    if certfile and keyfile:
        try:
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.load_cert_chain(certfile, keyfile)
            httpd.socket = context.wrap_socket(httpd.socket, server_side=True)
            logger.info(f"HTTPS server configured with cert: {certfile}")
            print(f"Starting Ansible HTTP Agent with HTTPS on port {port}...")
            print(f"Agent URL: https://localhost:{port}")
        except Exception as e:
            logger.error(f"Failed to configure HTTPS: {e}")
            print(f"Error configuring HTTPS: {e}")
            sys.exit(1)
    else:
        logger.warning("Running without SSL/TLS encryption!")
        print(f"Starting Ansible HTTP Agent with HTTP on port {port}...")
        print(f"Agent URL: http://localhost:{port}")
        print("Warning: Running without SSL/TLS encryption is insecure!")
    
    print("Press Ctrl+C to stop the server")
    logger.info(f"Server started on port {port}")
    
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down the server...")
        logger.info("Server shutdown requested")
        httpd.shutdown()
    except Exception as e:
        logger.error(f"Server error: {e}")
        sys.exit(1)


if __name__ == '__main__':
    main()
