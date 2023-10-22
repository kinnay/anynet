
from anynet import http, tls, tcp, xml
import pytest


def test_errors():
	assert issubclass(http.HTTPError, Exception)
	assert issubclass(http.HTTPResponseError, http.HTTPError)

def test_urlencode():
	assert http.urlencode("\0\xff\x7f").lower() == "%00%c3%bf%7f"

def test_urldecode():
	assert http.urldecode("%00%c3%bf%7f") == "\0\xff\x7f"
	assert http.urldecode("%00%C3%Bf%7F") == "\0\xff\x7f"
	assert http.urldecode("%3012%33") == "0123"
	assert http.urldecode("%25%%30%7G") == "%%0%7G"
	
def test_formdecode():
	assert http.formdecode("") == {}
	assert http.formdecode("a=b&b=a") == {
		"a": "b", "b": "a"
	}
	assert http.formdecode(
		"123%20456=%26%3d%3F&-_=-_&~="
	) == {"123 456": "&=?", "-_": "-_", "~": ""}
	assert http.formdecode(
		"123%20456=%26%3d%3F&-_=-_&~=", False
	) == {"123%20456": "%26%3d%3F", "-_": "-_", "~": ""}

def test_formencode():
	assert http.formencode({}) == ""
	assert http.formencode({"a": "b", "b": "a"}) == "a=b&b=a"
	assert http.formencode({
		"123 456": "&=?", "-_": "-_", "~": ""
	}) == "123%20456=%26%3D%3F&-_=-_&~="
	assert http.formencode({
		"123 456": "&=?", "-_": "-_", "~": ""
	}, False) == "123 456=&=?&-_=-_&~="


class TestHTTPMessage:
	def test_classes(self):
		assert issubclass(http.HTTPRequest, http.HTTPMessage)
		assert issubclass(http.HTTPResponse, http.HTTPMessage)
	
	def test_attributes(self):
		request = http.HTTPRequest()
		assert request.version == "HTTP/1.1"
		assert request.headers == {}
		assert request.body == b""
		assert request.text is None
		assert request.files is None
		assert request.boundary == "--------BOUNDARY--------"
		assert request.form is None
		assert request.rawform is None
		assert request.json is None
		assert request.xml is None


class TestHTTPRequest:
	def test_attributes(self):
		request = http.HTTPRequest()
		assert request.method == "GET"
		assert request.path == "/"
		assert request.params is None
		assert request.continue_threshold == 1024
		
	def test_encode(self):
		request = http.HTTPRequest()
		assert request.encode() == b"GET / HTTP/1.1\r\n\r\n"
	
	def test_encode_headers(self):
		request = http.HTTPRequest()
		assert request.encode_headers() == b"GET / HTTP/1.1\r\n\r\n"
	
	def test_encode_body(self):
		request = http.HTTPRequest()
		assert request.encode_body() == b""
	
	def test_classmethod(self):
		request = http.HTTPRequest.head("/test?x=1")
		assert request.method == "HEAD"
		assert request.path == "/test"
		assert request.params == {"x": "1"}

		request = http.HTTPRequest.get("/test?x=1")
		assert request.method == "GET"
		assert request.path == "/test"
		assert request.params == {"x": "1"}
		
		request = http.HTTPRequest.post("/post")
		assert request.method == "POST"
		assert request.path == "/post"
		
		request = http.HTTPRequest.put("/test/put")
		assert request.method == "PUT"
		assert request.path == "/test/put"
		
		request = http.HTTPRequest.patch("/delete")
		assert request.method == "PATCH"
		assert request.path == "/delete"
		
		request = http.HTTPRequest.delete("/")
		assert request.method == "DELETE"
		assert request.path == "/"


class TestHTTPResponse:
	def test_init(self):
		response = http.HTTPResponse(404)
		assert response.status_code == 404
		assert response.status_name == "Not Found"
	
	def test_success(self):
		response = http.HTTPResponse(500)
		assert not response.success()
		
		response = http.HTTPResponse(200)
		assert response.success()
	
	def test_error(self):
		response = http.HTTPResponse(404)
		assert response.error()
		
		response = http.HTTPResponse(201)
		assert not response.error()
	
	def test_raise_if_error(self):
		response = http.HTTPResponse()
		with pytest.raises(http.HTTPResponseError):
			response.raise_if_error()
			
			
class TestHTTPServer:
	@pytest.mark.anyio
	async def test_ok(self):
		async def handler(client, request):
			assert request.method == "GET"
			assert request.path == "/test/ok"
			response = http.HTTPResponse(200)
			return response
		
		async with http.serve(handler, "localhost", 12345):
			response = await http.get("localhost:12345/test/ok")
			assert response.success()
		
	@pytest.mark.anyio
	async def test_headers(self):
		async def handler(client, request):
			assert request.headers["X-Header-1"] == "test1"
			assert request.headers["X-Header-2"] == "test2"
			return http.HTTPResponse(200)
		
		async with http.serve(handler, "localhost", 12345):
			response = await http.get("localhost:12345", headers={
				"X-Header-1": "test1",
				"X-Header-2": "test2"
			})
			assert response.success()
	
	@pytest.mark.anyio
	async def test_status(self):
		async def handler(client, request):
			status = int(request.headers["X-Status-Code"])
			return http.HTTPResponse(status)
		
		async with http.serve(handler, "localhost", 12345):
			response = await http.get("localhost:12345", headers={
				"X-Status-Code": 404
			})
			assert response.status_code == 404
			assert response.status_name == "Not Found"
			assert response.error()
			
			response = await http.get("localhost:12345", headers={
				"X-Status-Code": 678
			})
			assert response.status_code == 678
			assert response.status_name == "Unknown"
			assert response.error()
	
	@pytest.mark.anyio
	async def test_exception(self):
		async def handler(client, request):
			raise ValueError("Oops")
		
		async with http.serve(handler, "localhost", 12345):
			response = await http.get("localhost:12345")
			assert response.status_code == 500
			assert response.status_name == "Internal Server Error"
	
	@pytest.mark.anyio
	async def test_body(self):
		async def handler(client, request):
			assert request.body == b"abcdef"
			response = http.HTTPResponse(200)
			response.body = request.body[::-1]
			return response
		
		async with http.serve(handler, "localhost", 12345):
			response = await http.get("localhost:12345", body=b"abcdef")
			assert response.success()
			assert response.body == b"fedcba"
	
	@pytest.mark.anyio
	async def test_text(self):
		async def handler(client, request):
			assert request.body == b"Hello"
			response = http.HTTPResponse(200)
			response.text = request.text.upper()
			return response
		
		async with http.serve(handler, "localhost", 12345):
			response = await http.get("localhost:12345", text="Hello")
			assert response.text == "HELLO"
	
	@pytest.mark.anyio
	async def test_methods(self):
		async def handler(client, request):
			response = http.HTTPResponse(200)
			if request.method != "HEAD":
				response.text = request.method
			return response
			
		async with http.serve(handler, "localhost", 12345):
			response = await http.head("localhost:12345")
			assert not response.text

			response = await http.get("localhost:12345")
			assert response.text == "GET"
			
			response = await http.post("localhost:12345")
			assert response.text == "POST"
			
			response = await http.put("localhost:12345")
			assert response.text == "PUT"
			
			response = await http.patch("localhost:12345")
			assert response.text == "PATCH"
			
			response = await http.delete("localhost:12345")
			assert response.text == "DELETE"
			
	@pytest.mark.anyio
	async def test_request(self):
		async def handler(client, request):
			assert request.path == "/path"
			response = http.HTTPResponse(200)
			response.body = request.body
			return response
		
		async with http.serve(handler, "localhost", 12345):
			request = http.HTTPRequest()
			request.body = b"test"
			request.path = "/path"
			
			response = await http.request("localhost:12345", request)
			assert response.body == b"test"
			
	@pytest.mark.anyio
	async def test_continue(self):
		async def handler(client, request):
			response = http.HTTPResponse(200)
			response.body = request.body
			return response
	
		async with http.serve(handler, "localhost", 12345):
			request = http.HTTPRequest()
			request.continue_threshold = 64
			request.body = b"a" * 80
			
			response = await http.request("localhost:12345", request)
			assert response.body == b"a" * 80
			
	@pytest.mark.anyio
	async def test_files(self):
		async def handler(client, request):
			response = http.HTTPResponse(200)
			response.files = {
				"response": request.files["filename"]
			}
			return response
		
		async with http.serve(handler, "localhost", 12345):
			response = await http.get(
				"localhost:12345", boundary="TEST",
				files={"filename": b"content"}
			)
			assert response.files == {
				"response": b"content"
			}
	
	@pytest.mark.anyio
	async def test_form(self):
		async def handler(client, request):
			response = http.HTTPResponse(200)
			response.form = {
				"$<result>": request.form["&value+=!"]
			}
			return response
			
		async with http.serve(handler, "localhost", 12345):
			response = await http.get("localhost:12345", form={
				"&value+=!": "???"
			})
			assert response.form["$<result>"] == "???"
	
	@pytest.mark.anyio
	async def test_rawform(self):
		async def handler(client, request):
			response = http.HTTPResponse(200)
			response.rawform = {
				"$<result>": request.rawform["value+!"]
			}
			return response
			
		async with http.serve(handler, "localhost", 12345):
			response = await http.get("localhost:12345", rawform={
				"value+!": "???"
			})
			assert response.rawform["$<result>"] == "???"
	
	@pytest.mark.anyio
	async def test_json(self):
		async def handler(client, request):
			response = http.HTTPResponse(200)
			response.json = {
				"result": request.json["value"]
			}
			return response
			
		async with http.serve(handler, "localhost", 12345):
			response = await http.get("localhost:12345", json={
				"value": True
			})
			assert response.json["result"] is True
	
	@pytest.mark.anyio
	async def test_xml(self):
		async def handler(client, request):
			assert request.xml.name == "value"
			tree = xml.XMLTree("result")
			tree.text = request.xml.text
			response = http.HTTPResponse(200)
			response.xml = tree
			return response
		
		async with http.serve(handler, "localhost", 12345):
			tree = xml.XMLTree("value")
			tree.text = "12345"
			response = await http.get("localhost:12345", xml=tree)
			assert response.xml.name == "result"
			assert response.xml.text == "12345"
			
	@pytest.mark.anyio
	async def test_certificate(self):
		# Create a self signed server certificate
		serverkey = tls.TLSPrivateKey.generate()
		servercert = tls.TLSCertificate.generate(serverkey)
		servercert.subject["CN"] = "localhost"
		servercert.issuer["CN"] = "localhost"
		servercert.sign(serverkey)
		
		# Create a certificate authority for the client certificate
		authoritykey = tls.TLSPrivateKey.generate()
		authoritycert = tls.TLSCertificate.generate(authoritykey)
		authoritycert.subject["CN"] = "authority"
		authoritycert.issuer["CN"] = "authority"
		authoritycert.sign(authoritykey)
		
		# Create a client certificate and sign it
		clientkey = tls.TLSPrivateKey.generate()
		clientcert = tls.TLSCertificate.generate(clientkey)
		clientcert.subject["CN"] = "testclient"
		clientcert.issuer["CN"] = "authority"
		clientcert.sign(authoritykey)
		
		# Create TLS context for the server
		servercontext = tls.TLSContext()
		servercontext.set_certificate(servercert, serverkey)
		servercontext.set_authority(authoritycert)
		
		clientcontext = tls.TLSContext()
		clientcontext.set_certificate(clientcert, clientkey)
		clientcontext.set_authority(servercert)
		
		async def handler(client, request):
			cert = client.remote_certificate()
			assert cert.subject["CN"] == "testclient"
			return http.HTTPResponse(200)
		
		async with http.serve(handler, "localhost", 12345, servercontext):
			response = await http.get("localhost:12345", context=clientcontext)
			assert response.success()


class TestHTTPMisc:
	@pytest.mark.anyio
	async def test_response_no_length(self):
		async def handler(client):
			req = b""
			while b"\r\n\r\n" not in req:
				req += await client.recv()
			await client.send(b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\nTesting")
		
		async with tcp.serve(handler, "localhost", 12345):
			response = await http.get("localhost:12345")
			assert response.text == "Testing"
