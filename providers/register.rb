# encoding: UTF-8
#
# Cookbook Name:: openstack-identity
# Provider:: register
#
# Copyright 2012, Rackspace US, Inc.
# Copyright 2012-2013, AT&T Services, Inc.
# Copyright 2013, Opscode, Inc.
# Copyright 2013, Craig Tracey <craigtracey@gmail.com>
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

require 'chef/mixin/shell_out'
include Chef::Mixin::ShellOut
include ::Openstack

# DO-101 (Max)
#
# the most of the code was rewritten to support both keystone v2 and v3.
# There are no inline comments. To see the changes the easiest way is to compare with the previous version 12.0.0 (git diff).

private

def generate_boot_creds(resource)
  # DO-101
  if node['openstack']['api']['auth']['version'] == 'v3.0'
    {
      'OS_SERVICE_ENDPOINT' => resource.auth_uri,
      'OS_SERVICE_TOKEN' => resource.bootstrap_token,
      'OS_USER_DOMAIN_ID' => node['openstack']['identity']['identity']['default_domain_id'],
      'OS_PROJECT_DOMAIN_ID' => node['openstack']['identity']['identity']['default_domain_id'],
      'OS_IDENTITY_API_VERSION' => '3',
      # there might be a bug in openstackclient-1.7.0, it doesn't work with OS_SERVICE_ENDPOINT and OS_SERVICE_TOKEN, we set OS_URL and OS_TOKEN to overcome this problem
      # probably we will remove OS_URL and OS_TOKEN if/once we upgrade to the more recent openstackclient
      'OS_URL' => resource.auth_uri,
      'OS_TOKEN' => resource.bootstrap_token
    }
  else
    {
      'OS_SERVICE_ENDPOINT' => resource.auth_uri,
      'OS_SERVICE_TOKEN' => resource.bootstrap_token,
      # there might be a bug in openstackclient-1.7.0, it doesn't work with OS_SERVICE_ENDPOINT and OS_SERVICE_TOKEN, we set OS_URL and OS_TOKEN to overcome this problem
      # probably we will remove OS_URL and OS_TOKEN if/once we upgrade to the more recent openstackclient
      'OS_URL' => resource.auth_uri,
      'OS_TOKEN' => resource.bootstrap_token
    }
  end
end

private

def generate_admin_creds(resource)
  identity_endpoint = resource.identity_endpoint
  # DO-101
  if node['openstack']['api']['auth']['version'] == 'v3.0'
    identity_endpoint = endpoint('identity-admin').to_s unless identity_endpoint
    { 
      'OS_USERNAME' => resource.admin_user,
      'OS_PASSWORD' => resource.admin_pass,
      'OS_TENANT_NAME' => resource.admin_tenant_name,
      'OS_PROJECT_NAME' => resource.admin_tenant_name,
      'OS_AUTH_URL' => identity_endpoint,
      'OS_USER_DOMAIN_ID' => node['openstack']['identity']['identity']['default_domain_id'],
      'OS_PROJECT_DOMAIN_ID' => node['openstack']['identity']['identity']['default_domain_id'],
      'OS_IDENTITY_API_VERSION' => '3'
    }
  else
    identity_endpoint = endpoint('identity-admin').to_s unless identity_endpoint
    {
      'OS_USERNAME' => resource.admin_user,
      'OS_PASSWORD' => resource.admin_pass,
      'OS_TENANT_NAME' => resource.admin_tenant_name,
      'OS_AUTH_URL' => identity_endpoint
    }
  end
end

private

def generate_user_creds(resource)
  identity_endpoint = resource.identity_endpoint
  # DO-101
  if node['openstack']['api']['auth']['version'] == 'v3.0'
    identity_endpoint = endpoint('identity-api').to_s unless identity_endpoint
    if resource.domain_name
      {
        'OS_USERNAME' => resource.user_name,
        'OS_PASSWORD' => resource.user_pass,
        'OS_TENANT_NAME' => resource.tenant_name,
        'OS_PROJECT_NAME' => resource.tenant_name,
        'OS_AUTH_URL' => identity_endpoint,
        'OS_USER_DOMAIN_NAME' => resource.domain_name,
        'OS_PROJECT_DOMAIN_NAME' => resource.domain_name,
        'OS_IDENTITY_API_VERSION' => '3'
      }
    else
      {
        'OS_USERNAME' => resource.user_name,
        'OS_PASSWORD' => resource.user_pass,
        'OS_TENANT_NAME' => resource.tenant_name,
        'OS_PROJECT_NAME' => resource.tenant_name,
        'OS_AUTH_URL' => identity_endpoint,
        'OS_USER_DOMAIN_ID' => node['openstack']['identity']['identity']['default_domain_id'],
        'OS_PROJECT_DOMAIN_ID' => node['openstack']['identity']['identity']['default_domain_id'],
        'OS_IDENTITY_API_VERSION' => '3'
      }
    end
  else
    identity_endpoint = endpoint('identity-api').to_s unless identity_endpoint
    {
      'OS_USERNAME' => resource.user_name,
      'OS_PASSWORD' => resource.user_pass,
      'OS_TENANT_NAME' => resource.tenant_name,
      'OS_AUTH_URL' => identity_endpoint
    }
  end
end

private

def get_env(resource, env = 'boot')
  case env
  when 'boot'
    generate_boot_creds(resource)
  when 'user'
    generate_user_creds(resource)
  when 'admin'
    generate_admin_creds(resource)
  end
end

private

def identity_command(resource, cmd, args = {}, env = 'boot', cmd_args = [])
  keystonecmd = ['openstack'] << '--insecure' << cmd
  args.each do |key, val|
    keystonecmd << "--#{key}" unless key.empty?
    keystonecmd << val.to_s
  end
  cmd_args.each do |cmd_arg|
    keystonecmd << cmd_arg.to_s
  end
  cmd_env = get_env(resource, env)
  Chef::Log.debug("Running identity command: #{keystonecmd} env: " + cmd_env.to_s)
  rc = shell_out(keystonecmd, env: cmd_env)
  fail "#{rc.stderr} (#{rc.exitstatus})" if rc.exitstatus != 0
  rc.stdout
end

private

def identity_uuid(resource, type, key, value, args = {}, uuid_field = 'ID')  # rubocop: disable ParameterLists
  rc = nil
  begin
    output = identity_command resource, "#{type} list", args
    output = prettytable_to_array(output)
    rc = (type == 'endpoint') ? (search_uuid(output, uuid_field, key => value, 'Region' => resource.endpoint_region)) : (search_uuid(output, uuid_field, key => value))
  rescue RuntimeError => e
    raise "Could not lookup uuid for #{type}:#{key}=>#{value}. Error was #{e.message}"
  end
  rc
end

private

def search_uuid(output, uuid_field, required_hash = {})
  rc = nil
  output.each do |obj|
    rc = obj[uuid_field] if obj.key?(uuid_field) && required_hash.values - obj.values_at(*required_hash.keys) == []
  end
  rc
end

private

def service_need_updated?(resource, args = {}, uuid_field = 'ID')
  begin
    output = identity_command resource, 'service list', args
    output = prettytable_to_array(output)
    return search_uuid(output, uuid_field, 'Name' => resource.service_name).nil?
  rescue RuntimeError => e
    raise "Could not check service attributes for service: type => #{resource.service_type}, name => #{resource.service_name}. Error was #{e.message}"
  end
  false
end

private

def endpoint_need_updated?(resource, key, value, args = {}, uuid_field = 'ID')
  begin
    output = identity_command resource, 'endpoint list', args
    output = prettytable_to_array(output)
    if node['openstack']['api']['auth']['version'] == 'v3.0'
      endpoint_url = eval("resource.endpoint_"+"#{args['interface']}"+"url")
      return search_uuid(output, uuid_field, key => value, 'Region' => resource.endpoint_region, 'URL' => endpoint_url).nil?
    else
      return search_uuid(output, uuid_field, key => value, 'Region' => resource.endpoint_region, 'PublicURL' => resource.endpoint_publicurl, 'InternalURL' => resource.endpoint_internalurl, 'AdminURL' => resource.endpoint_adminurl).nil?
    end
  rescue RuntimeError => e
    raise "Could not check endpoint attributes for endpoint:#{key}=>#{value}. Error was #{e.message}"
  end
  false
end

action :create_service do
  new_resource.updated_by_last_action(false)
  if node['openstack']['identity']['catalog']['backend'] == 'templated'
    Chef::Log.info('Skipping service creation - templated catalog backend in use.')
  else
    begin
      service_uuid = identity_uuid new_resource, 'service', 'Type', new_resource.service_type
      need_updated = false
      if service_uuid
        Chef::Log.info("Service Type '#{new_resource.service_type}' already exists..")
        Chef::Log.info("Service UUID: #{service_uuid}")
        need_updated = service_need_updated? new_resource
        if need_updated
          Chef::Log.info("Service Type '#{new_resource.service_type}' needs to be updated, delete it first.")
          identity_command(new_resource, 'service delete',
                           '' => service_uuid)
        end
      end
      unless service_uuid && !need_updated
        identity_command(new_resource, 'service create',
                         'name' => new_resource.service_name,
                         'description' => new_resource.service_description,
                         '' => new_resource.service_type)
        Chef::Log.info("Created service '#{new_resource.service_name}'")
        new_resource.updated_by_last_action(true)
      end
    rescue StandardError => e
      raise "Unable to create service '#{new_resource.service_name}' Error:" + e.message
    end
  end
end

action :create_endpoint do
  new_resource.updated_by_last_action(false)
  if node['openstack']['identity']['catalog']['backend'] == 'templated'
    Chef::Log.info('Skipping endpoint creation - templated catalog backend in use.')
  else
    begin
      service_uuid = identity_uuid new_resource, 'service', 'Type', new_resource.service_type
      fail "Unable to find service type '#{new_resource.service_type}'" unless service_uuid

      if node['openstack']['api']['auth']['version'] == 'v3.0'
        interfaces = ['internal', 'public', 'admin']
        interfaces.each do |interface|
          endpoint_uuid = identity_uuid(new_resource, 'endpoint', 'Service Type', new_resource.service_type, 
                                        'interface' => interface)
          need_updated = false
          if endpoint_uuid
            Chef::Log.info("'#{interface}' endpoint already exists for Service Type '#{new_resource.service_type}'")
          
            need_updated = endpoint_need_updated?(new_resource, 'ID', endpoint_uuid,
                                             'interface' => interface)
            if need_updated
              Chef::Log.info("'#{interface}' endpoint for Service Type '#{new_resource.service_type}' needs to be updated")
              endpoint_url = eval("new_resource.endpoint_"+"#{interface}"+"url")
              identity_command(new_resource, 'endpoint set',
                            'region' => new_resource.endpoint_region,
                            'interface' => interface,
                            'service' => new_resource.service_type,
                            'url' => endpoint_url,
                            '' => endpoint_uuid)
              Chef::Log.info("Updated '#{interface}' endpoint for service type '#{new_resource.service_type}'")
            end
          end

          unless endpoint_uuid
            endpoint_url = eval("new_resource.endpoint_"+"#{interface}"+"url")
            Chef::Log.info("endpoint_url == #{endpoint_url}")
            cmd_args = ["#{new_resource.service_type}"] << "#{interface}" << "#{endpoint_url}"
            identity_command(new_resource, 'endpoint create',
                        { 'region' => new_resource.endpoint_region },
                        'boot', cmd_args)
            Chef::Log.info("Created '#{interface}' endpoint for service type '#{new_resource.service_type}'")
            new_resource.updated_by_last_action(true)
          end

        end
      else

        endpoint_uuid = identity_uuid new_resource, 'endpoint', 'Service Type', new_resource.service_type
        need_updated = false

        if endpoint_uuid
          Chef::Log.info("Endpoint already exists for Service Type '#{new_resource.service_type}'.")
          need_updated = endpoint_need_updated?(new_resource, 'ID', endpoint_uuid,
                                             '' => '--long')
          if need_updated
            Chef::Log.info("Endpoint for Service Type '#{new_resource.service_type}' needs to be updated, delete it first.")
            identity_command(new_resource, 'endpoint delete',
                           '' => endpoint_uuid)
          end
        end
        unless endpoint_uuid && !need_updated
          identity_command(new_resource, 'endpoint create',
                         'region' => new_resource.endpoint_region,
                         'publicurl' => new_resource.endpoint_publicurl,
                         'internalurl' => new_resource.endpoint_internalurl,
                         'adminurl' => new_resource.endpoint_adminurl,
                         '' => service_uuid)
          Chef::Log.info("Created endpoint for service type '#{new_resource.service_type}'")
          new_resource.updated_by_last_action(true)
        end
      end
    rescue StandardError => e
      raise "Unable to create endpoint for service type '#{new_resource.service_type}' Error: " + e.message
    end
  end
end

action :create_tenant do
  begin
    new_resource.updated_by_last_action(false)
    tenant_uuid = identity_uuid new_resource, 'project', 'Name', new_resource.tenant_name

    if tenant_uuid
      Chef::Log.info("Tenant '#{new_resource.tenant_name}' already exists.. Not creating.")
      Chef::Log.info("Tenant UUID: #{tenant_uuid}") if tenant_uuid
    else
      if node['openstack']['api']['auth']['version'] == 'v3.0'
        if new_resource.domain_name
          identity_command(new_resource, 'project create',
                            { 'description' => new_resource.tenant_description,
                              'domain' => new_resource.domain_name,
                              '' => new_resource.tenant_name } )
          Chef::Log.info("Created project '#{new_resource.tenant_name}' for the default domain")
          new_resource.updated_by_last_action(true)
        else
          identity_command(new_resource, 'project create',
                            { 'description' => new_resource.tenant_description,
                              'domain' => node['openstack']['identity']['identity']['default_domain_id'],
                              '' => new_resource.tenant_name } )
          Chef::Log.info("Created project '#{new_resource.tenant_name}' for the default domain")
          new_resource.updated_by_last_action(true)
        end
      else
        identity_command(new_resource, 'project create',
                       { 'description' => new_resource.tenant_description,
                       '' => new_resource.tenant_name } )
        Chef::Log.info("Created tenant '#{new_resource.tenant_name}'")
        new_resource.updated_by_last_action(true)
      end
    end
  rescue StandardError => e
    raise "Unable to create tenant '#{new_resource.tenant_name}' Error: " + e.message
  end
end

action :create_role do
  begin
    new_resource.updated_by_last_action(false)
    role_uuid = identity_uuid new_resource, 'role', 'Name', new_resource.role_name

    if role_uuid
      Chef::Log.info("Role '#{new_resource.role_name}' already exists.. Not creating.")
      Chef::Log.info("Role UUID: #{role_uuid}")
    else
      identity_command(new_resource, 'role create',
                       '' => new_resource.role_name)
      Chef::Log.info("Created Role '#{new_resource.role_name}'")
      new_resource.updated_by_last_action(true)
    end
  rescue StandardError => e
    raise "Unable to create role '#{new_resource.role_name}' Error: " + e.message
  end
end

action :create_user do
  begin
    new_resource.updated_by_last_action(false)

    output = identity_command(new_resource, 'user list')
    users = prettytable_to_array output
    user_found = false
    users.each do |user|
      user_found = true if user['Name'] == new_resource.user_name
    end

    if user_found
      Chef::Log.info("User '#{new_resource.user_name}' already exists")
      begin
        # Check if password is already updated by getting a token
        identity_command(new_resource, 'token issue', {}, 'user')
      rescue StandardError => e
        Chef::Log.debug('Get token error:' + e.message)
        Chef::Log.info("Sync password for user '#{new_resource.user_name}'")
        identity_command(new_resource, 'user set',
                         'password' => new_resource.user_pass,
                         '' => new_resource.user_name)
        new_resource.updated_by_last_action(true)
      end
      next
    end

    if new_resource.domain_name
      identity_command(new_resource, 'user create',
                       'domain' => new_resource.domain_name,
                       'project' => new_resource.tenant_name,
                       'password' => new_resource.user_pass,
                       '' => new_resource.user_name)
    else
      if node['openstack']['api']['auth']['version'] == 'v3.0'
        identity_command(new_resource, 'user create',
                         'domain' => node['openstack']['identity']['identity']['default_domain_id'],
                         'project' => new_resource.tenant_name,
                         'password' => new_resource.user_pass,
                         '' => new_resource.user_name)
      else
        identity_command(new_resource, 'user create',
                 'project' => new_resource.tenant_name,
                 'password' => new_resource.user_pass,
                 '' => new_resource.user_name)
      end
    end

    if new_resource.user_enabled
      identity_command(new_resource, 'user set',
                       'enable' => new_resource.user_name)
    else
      identity_command(new_resource, 'user set',
                       'disable' => new_resource.user_name)
    end
    Chef::Log.info("Created user '#{new_resource.user_name}' for tenant '#{new_resource.tenant_name}'")
    new_resource.updated_by_last_action(true)
  rescue StandardError => e
    raise "Unable to create user '#{new_resource.user_name}' for tenant '#{new_resource.tenant_name}' Error: " + e.message
  end
end

action :grant_role do
  begin
    new_resource.updated_by_last_action(false)

    role_uuid = identity_uuid new_resource, 'role', 'Name', new_resource.role_name
    fail "Unable to find role '#{new_resource.role_name}'" unless role_uuid

    if new_resource.tenant_name
      assigned_role_uuid = identity_uuid(new_resource, 'role', 'Name',
                                         new_resource.role_name,
                                         'project' => new_resource.tenant_name,
                                         'user' => new_resource.user_name)
      if role_uuid == assigned_role_uuid
        Chef::Log.info("Role '#{new_resource.role_name}' already granted to User '#{new_resource.user_name}' in Tenant '#{new_resource.tenant_name}'")
      else
        identity_command(new_resource, 'role add',
                         'project' => new_resource.tenant_name,
                         'user' => new_resource.user_name,
                         '' => role_uuid)
        Chef::Log.info("Granted Role '#{new_resource.role_name}' to User '#{new_resource.user_name}' in Tenant '#{new_resource.tenant_name}'")
        new_resource.updated_by_last_action(true)
      end
    elsif new_resource.domain_name
      assigned_role_uuid = identity_uuid(new_resource, 'role', 'Name',
                                         new_resource.role_name,
                                         'domain' => new_resource.domain_name,
                                         'user' => new_resource.user_name)
      if role_uuid == assigned_role_uuid
        Chef::Log.info("Role '#{new_resource.role_name}' already granted to User '#{new_resource.user_name}' in Domain '#{new_resource.domain_name}'")
      else
        identity_command(new_resource, 'role add',
                         'domain' => new_resource.domain_name,
                         'user' => new_resource.user_name,
                         '' => role_uuid)
        Chef::Log.info("Granted Role '#{new_resource.role_name}' to User '#{new_resource.user_name}' in Domain '#{new_resource.domain_name}'")
        new_resource.updated_by_last_action(true)
      end
    end
  rescue StandardError => e
    raise "Unable to grant role '#{new_resource.role_name}' to user '#{new_resource.user_name}' Error: " + e.message
  end
end

action :create_ec2_credentials do
  begin
    new_resource.updated_by_last_action(false)
    tenant_uuid = identity_uuid new_resource, 'project', 'Name', new_resource.tenant_name
    fail "Unable to find tenant '#{new_resource.tenant_name}'" unless tenant_uuid

    user_uuid = identity_uuid(new_resource, 'user', 'Name',
                              new_resource.user_name,
                              'project' => tenant_uuid)
    fail "Unable to find user '#{new_resource.user_name}' with tenant '#{new_resource.tenant_name}'" unless user_uuid

    # this is not really a uuid, but this will work nonetheless
    access = identity_uuid new_resource, 'ec2 credentials', 'Project ID', tenant_uuid, { 'user' => user_uuid }, 'Access'
    if access
      Chef::Log.info("EC2 credentials already exist for '#{new_resource.user_name}' in tenant '#{new_resource.tenant_name}'")
    else
      output = identity_command(new_resource, 'ec2 credentials create',
                              { 'user' => user_uuid,
                                'project' => tenant_uuid })
      Chef::Log.info("Created EC2 Credentials for User '#{new_resource.user_name}' in Tenant '#{new_resource.tenant_name}'")
      data = prettytable_to_array(output)

      if node['openstack']['api']['auth']['version'] == 'v3.0' and data.length != 6
        fail "Got bad data when creating ec2 credentials for #{new_resource.user_name} Data: #{data}."
      elsif node['openstack']['api']['auth']['version'] != 'v3.0' and data.length != 5
        fail "Got bad data when creating ec2 credentials for #{new_resource.user_name} Data: #{data}."
      else
        # Update node attributes
        node.set['credentials']['EC2'][new_resource.user_name]['access'] = data[0]['access']
        node.set['credentials']['EC2'][new_resource.user_name]['secret'] = data[0]['secret']
        node.save unless Chef::Config[:solo]
        new_resource.updated_by_last_action(true)
      end
    end
  rescue StandardError => e
    raise "Unable to create EC2 Credentials for User '#{new_resource.user_name}' in Tenant '#{new_resource.tenant_name}' Error: " + e.message
  end
end


action :create_domain do
  if node['openstack']['api']['auth']['version'] != 'v3.0'
    Chef::Log.info("Domains are not supported. To use domains, switch to identity API v3.0")
    fail
  end

  begin
    new_resource.updated_by_last_action(false)
    domain_uuid = identity_uuid new_resource, 'domain', 'Name', new_resource.domain_name

    if domain_uuid
      Chef::Log.info("Domain '#{new_resource.domain_name}' already exists.. Not creating.")
      Chef::Log.info("Domain UUID: #{domain_uuid}") if domain_uuid
    else
      identity_command(new_resource, 'domain create',
                        { 'description' => new_resource.domain_description,
                          '' => new_resource.domain_name } )
      Chef::Log.info("Created domain '#{new_resource.domain_name}")
      new_resource.updated_by_last_action(true)
    end
  rescue StandardError => e
    raise "Unable to create domain '#{new_resource.domain_name}' Error: " + e.message
  end
end
