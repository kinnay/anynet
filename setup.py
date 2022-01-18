
import setuptools

long_description = \
	"This is a simple asynchronous networking library that " \
	"I'm using for hobby projects. It's based on anyio, so " \
	"it can be used together with either asyncio or trio."

setuptools.setup(
	name = "anynet",
	version = "0.0.12",
	description = "Networking library based on anyio",
	long_description = long_description,
	author = "Yannik Marchand",
	author_email = "ymarchand@me.com",
	url = "https://github.com/kinnay/anynet",
	packages = ["anynet"],
	license = "MIT",
	
	install_requires=[
		"anyio >= 3.1.0",
		"cryptography",
		"pyopenssl",
		"netifaces",
		"pycryptodome",
		"multidict"
	]
)
