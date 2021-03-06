from functools import wraps
import time
import hashlib

from flask import g, request, abort, make_response

from .. import PatreonFrontend

def initialize(
		config,
		accounts,
		access_log,
		engine,
		install=False,
		connection=None,
	):
	g.patreon = PatreonFrontend(
		config,
		accounts,
		access_log,
		engine,
		install=install,
		connection=connection,
	)

# require objects or abort
def require_client(id):
	try:
		client = g.patreon.require_client(id)
	except ValueError as e:
		abort(404, str(e))
	else:
		return client
