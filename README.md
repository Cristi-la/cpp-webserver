# cpp-webserver
The ccp-web server application is a simple web server. I developed it to learn how to work with sockets in a low-level language like C++.
Server Functionalities

### Web Server Functionality Support

    HTTP Request Handling: The server can receive and parse HTTP requests (methods, headers, body).
    Response Generation: The server can generate and send responses with specific statuses, headers, and bodies.
    Graceful Shutdown: The server supports graceful shutdown using the SIGINT signal.
    Logging: The server creates a log file to record server activities.

### GET Functionality

    Serving Static Files: The server can serve static files.
    Directory Indexing: If the requested path is a directory, the server will try to serve an index.html file from the specified directory (if it exists).
    Serving Various File Types: The server handles MIME types for different file types.
    Query Parameter Handling: The server can process query parameters like ?name=value&name1=valueX.

### POST Functionality

    Form Data Processing: The server handles form data submitted with application/x-www-form-urlencoded.
    JSON Data Processing: The server processes JSON data submitted with application/json.

### HTTP Protocol Support

    Status Codes: The server returns appropriate HTTP status codes.
    Basic HTTP Headers: The server supports returning basic HTTP headers (Content-Type, Content-Length).

## Disclaimer

It is not recommended to use this server in a production environment, as the code may contain some bugs. However, it serves as a valuable learning resource for beginner C++ programmers.

### Compatibility

Unfortunately, this server can only be compiled on a Linux kernel due to the use of libraries that are supported only on Linux: <sys/socket.h>.

### Compilation Instructions

To compile the server, use the following command:

```bash
g++ -o server server.cpp -ljsoncpp
```