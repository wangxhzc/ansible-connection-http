# ansible-connection-http
ansible connection plugins http

start agent:

```shell
cd connection_agent
bash start.sh
```

inventory configuration:

```ini
10.0.0.1 ansible_connection=http ansible_user=<user> ansible_password=<password> ansible_http_agent_port=<agent-port> ansible_http_agent_scheme=https ansible_http_verify_ssl=false
# or
10.0.0.1 ansible_connection=http ansible_http_agent_port=<agent-port> ansible_http_agent_scheme=https ansible_http_verify_ssl=false
```

ansible.cfg:

```ini
[defaults]
connection_plugins = ./connection_plugins
```
