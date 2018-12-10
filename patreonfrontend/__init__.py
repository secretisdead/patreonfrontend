import time

from patreon import Patreon

class PatreonFrontend(Patreon):
	def __init__(self, config, accounts, access_log, engine, install=False):
		super().__init__(engine, config['db_prefix'], install)

		self.config = config
		self.accounts = accounts
		self.access_log = access_log

		self.callbacks = {}

	def add_callback(self, name, f):
		if name not in self.callbacks:
			self.callbacks[name] = []
		self.callbacks[name].append(f)

	# require object or raise
	def require_client(self, id):
		client = self.get_client(id)
		if not client:
			raise ValueError('Client not found')
		return client

	# extend patreon methods
	def get_client(self, client_id):
		client = super().get_client(client_id)
		if client:
			pass
		return client

	def search_clients(self, **kwargs):
		clients = super().search_clients(**kwargs)
		for client in clients.values():
			pass
		return clients

	def create_client(self, user_id='', **kwargs):
		client = super().create_client(**kwargs)
		self.access_log.create_log(
			scope='create_patreon_client',
			subject_id=user_id,
			object_id=client.id,
		)
		return client

	def update_client(self, user_id='', **kwargs):
		client = super().update_client(**kwargs)
		self.access_log.create_log(
			scope='update_patreon_client',
			subject_id=user_id,
			object_id=client.id,
		)
		return client

	def delete_client(self, client, user_id):
		super().delete_client(client.id_bytes)
		self.access_log.create_log(
			scope='delete_patreon_client',
			subject_id=user_id,
			object_id=client.id_bytes,
		)

	def refresh_client(self, client, redirect_uri, user_id=''):
		super().refresh_client(client, redirect_uri)
		self.access_log.create_log(
			scope='refresh_patreon_client',
			subject_id=user_id,
			object_id=client.id_bytes,
		)

	def edit_tier_permissions(self, user_id='', **kwargs):
		#TODO i don't care about allowing independent length and shareable for each permission
		#TODO but this is where it would go
		super().edit_tier_permissions(**kwargs)
		self.access_log.create_log(
			scope='edit_patreon_tier',
			subject_id=user_id,
			# bytes encode patreon's tier id
			object_id=str.encode(str(kwargs['tier_id'])),
		)

	def grant_client_permissions(self, client, user_id=''):
		self.access_log.create_log(
			scope='grant_patreon_client_permissions',
			subject_id=user_id,
			object_id=client.id_bytes,
		)
		self.populate_client_permissions(client)
		members = self.search_members(filter={
			'client_ids': client.id_bytes,
			'last_charged_after': 0,
			'last_charge_status': 'Paid',
			'charged_after_fulfilled': True,
		})
		patron_ids_to_members = {}
		for member in members.values():
			# skip members with no tier permissions
			if (
					member.tier_id not in client.tiers
					or not client.tiers[member.tier_id]['permissions']
				):
				continue
			if member.user_id not in patron_ids_to_members:
				patron_ids_to_members[member.user_id] = member
		authentications = self.accounts.search_authentications(
			filter={'values': list(patron_ids_to_members.keys())},
		)
		patron_ids_to_users = {}
		for authentication in authentications.values():
			patron_ids_to_users[int(authentication.value)] = authentication.user

		fulfilled_member_ids = []
		for patron_id, user in patron_ids_to_users.items():
			member = patron_ids_to_members[patron_id]
			fulfilled_member_ids.append(member.id_bytes)
			for permission in client.tiers[member.tier_id]['permissions']:
				current_time = time.time()
				valid_from_time = 0
				valid_until_time = 0
				for_user_id = ''
				if not permission['shareable']:
					# lock to specified user and set valid time range
					for_user_id = user.id_bytes
					valid_from_time = current_time - 1
					valid_until_time = current_time + permission['length']
				# use Users.create_auto_permission directly to avoid double logging
				# since this module logs its own created auto permissions
				auto_permission = super(
					type(self.accounts),
					self.accounts,
				).create_auto_permission(
				#auto_permission = self.accounts.create_auto_permission(
					user_id=for_user_id,
					scope=permission['scope'],
					group_bits=permission['group_bits'],
					duration=permission['length'],
					valid_from_time=valid_from_time,
					valid_until_time=valid_until_time,
				)
				self.access_log.create_log(
					scope='receive_patreon_tier_permission',
					subject_id=user.id_bytes,
					object_id=auto_permission.id_bytes,
				)
		if fulfilled_member_ids:
			self.set_members_last_fulfill_time(fulfilled_member_ids)
		self.accounts.sync_auto_permissions()

	def edit_benefit_permissions(self):
		#TODO patreon's api for working with benefits is nonexistant
		#TODO but it'll be better to use than tiers when they allow it
		pass
