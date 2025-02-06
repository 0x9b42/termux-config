from http.server import SimpleHTTPRequestHandler, HTTPServer

host = 'localhost'
port = 8084

class MyHandler(SimpleHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header('Content-type', 'text/html')
        self.end_headers()
        self.wfile.write(b'<h1>Hello Python</h1>')


server = HTTPServer((host, port), MyHandler)
print(f'serving http on http://{host}:{port}')
server.serve_forever()
