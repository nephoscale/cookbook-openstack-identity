# encoding: UTF-8
#
# Cookbook Name:: openstack-identity
# Recipe:: setup
#
# Copyright 2012, Rackspace US, Inc.
# Copyright 2012-2013, Opscode, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

require 'uri'
require 'mkmf'

class ::Chef::Recipe # rubocop:disable Documentation
  include ::Openstack
end

# TBD clean up item...
# These should probably become admin, internal, public endpoints for a
# single service 'identity-api'. To minimize impact, I propose that we
# defer that work until later.
identity_admin_endpoint = admin_endpoint 'identity-admin'
identity_internal_endpoint = internal_endpoint 'identity-internal'
identity_public_endpoint = public_endpoint 'identity-api'
auth_uri = ::URI.decode identity_admin_endpoint.to_s

# FIXME(invsblduck): RuboCop gating was enabled mid-review;
#   Remove these variables in a separate commit if really not needed.
admin_tenant_name = node['openstack']['identity']['admin_tenant_name']
admin_user = node['openstack']['identity']['admin_user']
admin_pass = get_password 'user', node['openstack']['identity']['admin_user']
# rubocop:enable UselessAssignment

bootstrap_token = get_password 'token', 'openstack_identity_bootstrap_token'

# FIXME(galstrom21): This needs to be refactored, to not use a
#   MultilineBlockChain.
# Register all the tenants specified in the users hash
node['openstack']['identity']['users'].values.map do |user_info|
  user_info['roles'].values.push(user_info['default_tenant'])
end.flatten.uniq.each do |tenant_name| # rubocop: disable MultilineBlockChain
  openstack_identity_register "Register '#{tenant_name}' Tenant" do
    auth_uri auth_uri
    bootstrap_token bootstrap_token
    tenant_name tenant_name
    tenant_description "#{tenant_name} Tenant"
    # DO-101. domain_name is used in case auth version is v3. otherwise it is skipped.
    domain_name "#{node['openstack']['identity']['identity']['default_domain_id']}"

    action :create_tenant
  end
end

# FIXME(galstrom21): This needs to be refactored, to not use a
#   MultilineBlockChain.
# Register all the roles from the users hash
node['openstack']['identity']['users'].values.map do |user_info|
  user_info['roles'].keys
end.flatten.uniq.each do |role_name| # rubocop: disable MultilineBlockChain
  openstack_identity_register "Register '#{role_name}' Role" do
    auth_uri auth_uri
    bootstrap_token bootstrap_token
    role_name role_name

    action :create_role
  end
end

node['openstack']['identity']['users'].each do |username, user_info|
  pwd = get_password 'user', username
  openstack_identity_register "Register '#{username}' User" do
    auth_uri auth_uri
    bootstrap_token bootstrap_token
    user_name username
    user_pass pwd
    tenant_name user_info['default_tenant']
    user_enabled true # Not required as this is the default

    action :create_user
  end

  user_info['roles'].each do |rolename, tenant_list|
    tenant_list.each do |tenantname|
      openstack_identity_register "Grant '#{rolename}' Role to '#{username}' User in '#{tenantname}' Tenant" do
        auth_uri auth_uri
        bootstrap_token bootstrap_token
        user_name username
        role_name rolename
        tenant_name tenantname

        action :grant_role
      end
    end
  end
end

# DO-101
# a few things to do for keystone v3
# Firstly, we need to assign admin role in default domain for admin account
#
# Secondly, _member_ role is not being created automatically with keystone v3
# https://bugs.launchpad.net/openstack-ansible/+bug/1474916
# to fix this we create _member_ role
# then we assign _member_ role to all users in service project
if node['openstack']['api']['auth']['version'] == 'v3.0' and !find_executable('openstack').nil?
  default_domain_name = node['openstack']['identity']['identity']['default_domain_name']
  admin_user = node['openstack']['identity']['admin_user']

  openstack_identity_register "Grant admin Role to '#{admin_user}' User in '#{default_domain_name}' Domain" do
    auth_uri auth_uri
    bootstrap_token bootstrap_token
    user_name admin_user
    role_name 'admin'
    domain_name default_domain_name
    action :grant_role
  end

  rolename = node['openstack']['identity']['member_role_name']

  openstack_identity_register "Register '#{rolename}' Role" do
    auth_uri auth_uri
    bootstrap_token bootstrap_token
    role_name rolename

    action :create_role
  end

  begin

    project = 'service'
    env = {
        'OS_URL'    => auth_uri,
        'OS_TOKEN'  => bootstrap_token,
        'OS_IDENTITY_API_VERSION' => '3'
    }

    users = prettytable_to_array(openstack_command('openstack', "user list --project #{project}", env))

    # assign _member role to service users
    users.each do |user|
      openstack_identity_register "Grant '#{rolename}' Role to '#{user['Name']}' User in '#{project}' Tenant" do
        auth_uri auth_uri
        bootstrap_token bootstrap_token
        user_name user['Name']
        role_name rolename
        tenant_name project

        action :grant_role
      end
    end

    # assign _member role to admin account
    project = node['openstack']['identity']['admin_tenant_name']
    openstack_identity_register "Grant '#{rolename}' Role to '#{node['openstack']['identity']['admin_user']}' User in '#{project}' Tenant" do
      auth_uri auth_uri
      bootstrap_token bootstrap_token
      user_name node['openstack']['identity']['admin_user']
      role_name rolename
      tenant_name project

      action :grant_role
    end
  rescue RuntimeError => e
    Chef::Log.info("Could not get the list of users in project #{project}. Error: #{e.message}")
  end
end
#


openstack_identity_register 'Register Identity Service' do
  auth_uri auth_uri
  bootstrap_token bootstrap_token
  service_name 'keystone'
  service_type 'identity'
  service_description 'Keystone Identity Service'

  action :create_service
  not_if { node['openstack']['identity']['catalog']['backend'] == 'templated' }
end

node.set['openstack']['identity']['adminURL'] = identity_admin_endpoint.to_s
node.set['openstack']['identity']['internalURL'] = identity_internal_endpoint.to_s
node.set['openstack']['identity']['publicURL'] = identity_public_endpoint.to_s

Chef::Log.info "Keystone AdminURL: #{identity_admin_endpoint}"
Chef::Log.info "Keystone InternalURL: #{identity_internal_endpoint}"
Chef::Log.info "Keystone PublicURL: #{identity_public_endpoint}"

openstack_identity_register 'Register Identity Endpoint' do
  auth_uri auth_uri
  bootstrap_token bootstrap_token
  service_type 'identity'
  endpoint_region node['openstack']['identity']['region']
  endpoint_adminurl node['openstack']['identity']['adminURL']
  endpoint_internalurl node['openstack']['identity']['internalURL']
  endpoint_publicurl node['openstack']['identity']['publicURL']

  action :create_endpoint
  not_if { node['openstack']['identity']['catalog']['backend'] == 'templated' }
end

node['openstack']['identity']['users'].each do |username, user_info|
  openstack_identity_register "Create EC2 credentials for '#{username}' user" do
    auth_uri auth_uri
    bootstrap_token bootstrap_token
    user_name username
    tenant_name user_info['default_tenant']
    admin_tenant_name admin_tenant_name
    admin_user admin_user
    admin_pass admin_pass

    action :create_ec2_credentials
  end
end
