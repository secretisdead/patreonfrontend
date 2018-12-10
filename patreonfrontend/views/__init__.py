from functools import wraps
import time
import hashlib

from flask import g, make_response, render_template
from flask import request, abort

from .. import PatreonFrontend

def initialize(config, accounts, access_log, engine, install):
	g.patreon = PatreonFrontend(
		config,
		accounts,
		access_log,
		engine,
		install=install,
	)

# require objects or abort
def require_client(id):
	try:
		client = g.patreon.require_client(id)
	except ValueError as e:
		abort(404, str(e))
	else:
		return client
