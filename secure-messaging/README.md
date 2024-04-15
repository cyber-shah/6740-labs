### Installation

We use only the yaml and cryptography libraries:

```
pip install -r requirements.txt
```

### Configuration

Configuration is in `config.yml`.

The only thing that you may realistically want to change for deployment is the `server.port` option. This is the port the server will listen on for incoming client connections. We picked a reasonable default, but it is possible some machines already have the port taken.

### Server

To launch the server:

```
python src/main_server.py
```

This should be done first, before the clients.

### Client

To launch a client:

```
python src/client.py username password
```

If the server doesn't recognize the username or password, it will reject it.

### Users

The server comes with three pre-registered users:

| Username | Password |
|-------------|-------|
| AzureDiamond      | hunter2   |
| liam      | superprivatepassword   |
| melt      | system   |
