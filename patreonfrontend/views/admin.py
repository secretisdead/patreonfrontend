import math
import json
import urllib
import time

from ipaddress import ip_address
from flask import Blueprint, render_template, abort, request, redirect
from flask import url_for, g
import dateutil.parser

from pagination_from_request import pagination_from_request
from . import require_client
from accounts.views import require_permissions

patreon_admin = Blueprint(
	'patreon_admin',
	__name__,
	template_folder='templates',
)

@patreon_admin.route('/clients/create', methods=['GET', 'POST'])
@require_permissions(group_names='admin')
def create_client():
	if 'POST' != request.method:
		return render_template('create_patreon_client.html')
	for field in [
			'client_id',
			'client_secret',
			'webhook_secret',
			'access_token',
			'refresh_token',
		]:
		if field not in request.form:
			abort(400, 'Missing client creation fields')
	client = g.patreon.create_client(
		user_id=g.patreon.accounts.current_user.id_bytes,
		client_id=request.form['client_id'],
		client_secret=request.form['client_secret'],
		webhook_secret=request.form['webhook_secret'],
		access_token=request.form['access_token'],
		refresh_token=request.form['refresh_token'],
	)
	return redirect(
		url_for(
			'patreon_admin.edit_client',
			client_id=client.id,
		),
		code=303,
	)

@patreon_admin.route('/clients/<client_id>/edit', methods=['GET', 'POST'])
@require_permissions(group_names='admin')
def edit_client(client_id):
	client = require_client(client_id)
	if 'POST' != request.method:
		return render_template(
			'edit_patreon_client.html',
			client_id=client.client_id,
			client_secret=client.client_secret,
			webhook_secret=client.webhook_secret,
			access_token=client.access_token,
			refresh_token=client.refresh_token,
		)
	for field in [
			'client_id',
			'client_secret',
			'webhook_secret',
			'access_token',
			'refresh_token',
		]:
		if field not in request.form:
			abort(400, 'Missing client creation fields')
	client = g.patreon.update_client(
		user_id=g.patreon.accounts.current_user.id_bytes,
		id=client.id,
		client_id=request.form['client_id'],
		client_secret=request.form['client_secret'],
		webhook_secret=request.form['webhook_secret'],
		access_token=request.form['access_token'],
		refresh_token=request.form['refresh_token'],
	)
	return redirect(
		url_for(
			'patreon_admin.edit_client',
			client_id=client.id,
		),
		code=303,
	)

@patreon_admin.route('/clients/<client_id>/remove')
@require_permissions(group_names='admin')
def remove_client(client_id):
	client = require_client(client_id)
	if 'confirm' not in request.args:
		return render_template(
			'confirm_remove_patreon_client.html',
			client=client,
		)
	g.patreon.delete_client(client, g.patreon.accounts.current_user.id_bytes)
	if 'redirect_uri' in request.args:
		return redirect(request.args['redirect_uri'], code=303)
	return redirect(url_for('patreon_admin.clients_list'), code=303)

@patreon_admin.route('/clients/<client_id>/refresh')
@require_permissions(group_names='admin')
def refresh_client(client_id):
	client = require_client(client_id)
	g.patreon.refresh_client(
		client,
		url_for('patreon_admin.clients_list'),
		g.patreon.accounts.current_user.id_bytes,
	)
	if 'redirect_uri' in request.args:
		return redirect(request.args['redirect_uri'], code=303)
	return redirect(url_for('patreon_admin.clients_list'), code=303)

@patreon_admin.route('/clients/<client_id>/grant')
@require_permissions(group_names='admin')
def grant_client_permissions(client_id):
	client = require_client(client_id)
	g.patreon.grant_client_permissions(
		client,
		g.patreon.accounts.current_user.id_bytes,
	)
	if 'redirect_uri' in request.args:
		return redirect(request.args['redirect_uri'], code=303)
	return redirect(url_for('patreon_admin.clients_list'), code=303)

@patreon_admin.route('/clients')
@require_permissions(group_names='admin')
def clients_list():
	search = {
		'id': '',
		'created_before': '',
		'created_after': '',
		'access_token_expired_before': '',
		'access_token_expired_after': '',
	}
	for field in search:
		if field in request.args:
			search[field] = request.args[field]

	filter = {}
	escape = lambda value: (
		value
			.replace('\\', '\\\\')
			.replace('_', '\_')
			.replace('%', '\%')
			.replace('-', '\-')
	)
	# for parsing datetime and timestamp from submitted form
	# filter fields are named the same as search fields
	time_fields = [
		'created_before',
		'created_after',
		'access_token_expired_before',
		'access_token_expired_after',
	]
	for field, value in search.items():
		if not value:
			continue
		if 'id' == field:
			filter['ids'] = value
		elif field in time_fields:
			try:
				parsed = dateutil.parser.parse(value)
			except ValueError:
				filter[field] = 'bad_query'
			else:
				search[field] = parsed.strftime('%Y-%m-%dT%H:%M:%S.%f%z')
				filter[field] = parsed.timestamp()
		elif 'client_id' == field:
			filter['client_ids'] = value
		elif 'creation_name' == field:
			filter['creation_names'] = '%' + escape(value) + '%'

	pagination = pagination_from_request('creation_time', 'desc', 0, 32)

	total_results = g.patreon.count_clients(filter=filter)
	results = g.patreon.search_clients(filter=filter, **pagination)

	for client in results.values():
		g.patreon.populate_client_tiers(client)
		g.patreon.populate_client_benefits(client)
		client.total_members = g.patreon.count_members(
			filter={'client_ids': client.id_bytes},
		)

	return render_template(
		'patreon_clients_list.html',
		results=results,
		search=search,
		pagination=pagination,
		total_results=total_results,
		total_pages=math.ceil(total_results / pagination['perpage']),
	)

@patreon_admin.route('/clients/<client_id>/tiers')
@require_permissions(group_names='admin')
def tiers_list(client_id):
	client = require_client(client_id)
	g.patreon.populate_client_tiers(client)
	return render_template(
		'patreon_tiers_list.html',
		client=client,
	)

@patreon_admin.route(
	'/clients/<client_id>/tiers/<tier_id>',
	methods=['GET', 'POST'],
)
@require_permissions(group_names='admin')
def edit_tier(client_id, tier_id):
	client = require_client(client_id)
	g.patreon.populate_client_tiers(client)
	tier_id = int(tier_id)
	if tier_id not in client.tiers:
		abort(404, 'Tier not found')
	tier = client.tiers[tier_id]
	g.patreon.populate_tier_permissions(tier)
	length = g.patreon.config['default_permission_length']
	selected_groups = []
	shareable = False
	if tier['permissions']:
		shareable = tier['permissions'][0]['shareable']
		length = tier['permissions'][0]['length']
		selected_groups = {}
		for permission in tier['permissions']:
			if permission['scope'] not in selected_groups:
				selected_groups[permission['scope']] = []
			for name, bit in g.patreon.accounts.group_names_to_bits.items():
				if g.patreon.accounts.contains_all_bits(
						permission['group_bits'],
						bit,
					):
					selected_groups[permission['scope']].append(name)
	if 'POST' != request.method:
		return render_template(
			'edit_patreon_tier.html',
			client=client,
			tier=tier,
			length=length,
			shareable=shareable,
			groups=g.patreon.accounts.available_groups,
			selected_groups=selected_groups,
		)
	length = int(request.form['length'])
	shareable = ('shareable' in request.form)
	group_bits = {}
	for scope in g.patreon.accounts.available_scopes:
		if scope not in group_bits:
			group_bits[scope] = 0
		for name, bit in g.patreon.accounts.group_names_to_bits.items():
			if 'scope_' + scope + '_group_' + name in request.form:
				group_bits[scope] = g.patreon.accounts.combine_groups(
					bits=[
						group_bits[scope],
						bit,
					],
				)
	g.patreon.edit_tier_permissions(
		client_id=client.id_bytes,
		tier_id=tier['id'],
		length=length,
		shareable=shareable,
		group_bits=group_bits,
		user_id=g.patreon.accounts.current_user.id_bytes,
	)
	return redirect(
		url_for(
			'patreon_admin.edit_tier',
			client_id=client.id,
			tier_id=tier['id'],
		),
		code=303,
	)

@patreon_admin.route('/clients/<client_id>/benefits')
@require_permissions(group_names='admin')
def benefits_list(client_id):
	client = require_client(client_id)
	g.patreon.populate_client_tiers(client)
	g.patreon.populate_client_benefits(client)
	return render_template(
		'patreon_benefits_list.html',
		client=client,
	)

@patreon_admin.route('/members')
@require_permissions(group_names='admin')
def members_list():
	search = {
		'id': '',
		'client_id': '',
		'campaign_id': '',
		'tier_id': '',
		'name': '',
		'amount_cents_more_than': '',
		'amount_cents_less_than': '',
		'last_charged_before': '',
		'last_fulfilled_before': '',
		'last_fulfilled_after': '',
		'last_charged_after': '',
		'last_charge_status': '',
		'lifetime_support_cents_more_than': '',
		'lifetime_support_cents_less_than': '',
		'pledged_before': '',
		'pledged_after': '',
	}
	for field in search:
		if field in request.args:
			search[field] = request.args[field]

	filter = {}
	escape = lambda value: (
		value
			.replace('\\', '\\\\')
			.replace('_', '\_')
			.replace('%', '\%')
			.replace('-', '\-')
	)
	# for parsing datetime and timestamp from submitted form
	# filter fields are named the same as search fields
	time_fields = [
		'last_fulfilled_before',
		'last_fulfilled_after',
		'last_charged_before',
		'last_charged_after',
		'pledged_before',
		'pledged_after',
	]
	for field, value in search.items():
		if not value:
			continue
		if 'id' == field:
			filter['ids'] = value
		elif field in time_fields:
			try:
				parsed = dateutil.parser.parse(value)
			except ValueError:
				filter[field] = 'bad_query'
			else:
				search[field] = parsed.strftime('%Y-%m-%dT%H:%M:%S.%f%z')
				filter[field] = parsed.timestamp()
		elif 'client_id' == field:
			filter['client_ids'] = value
		elif 'campaign_id' == field:
			filter['campaign_ids'] = value
		elif 'tier_id' == field:
			filter['tier_ids'] = value
		elif 'name' == field:
			filter['names'] = '%' + escape(value) + '%'
		elif 'last_charge_status' == field:
			filter['last_charge_status'] = value

	pagination = pagination_from_request('pledge_relationship_start_time', 'desc', 0, 32)

	total_results = g.patreon.count_members(filter=filter)
	results = g.patreon.search_members(filter=filter, **pagination)

	client_ids = []
	patron_ids = []
	for result in results.values():
		if result.client_id not in client_ids:
			client_ids.append(result.client_id)
		if result.user_id not in patron_ids:
			patron_ids.append(result.user_id)
	clients = g.patreon.search_clients(
		filter={'ids': client_ids},
	)
	for client in clients.values():
		g.patreon.populate_client_tiers(client)
	authentications = g.patreon.accounts.search_authentications(
		filter={'values': patron_ids},
	)
	patron_ids_to_users = {}
	for authentication in authentications.values():
		patron_ids_to_users[int(authentication.value)] = authentication.user
	return render_template(
		'patreon_members_list.html',
		results=results,
		search=search,
		pagination=pagination,
		total_results=total_results,
		total_pages=math.ceil(total_results / pagination['perpage']),
		clients=clients,
		patron_ids_to_users=patron_ids_to_users,
	)
