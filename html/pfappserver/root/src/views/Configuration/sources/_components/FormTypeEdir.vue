<template>
  <base-form
    :form="form"
    :meta="meta"
    :schema="schema"
    :isLoading="isLoading"
  >
    <form-group-identifier namespace="id"
                           :column-label="$i18n.t('Name')"
                           :disabled="!isNew && !isClone"
    />

    <form-group-description namespace="description"
                            :column-label="$i18n.t('Description')"
    />

    <form-group-host-port-encryption :namespaces="['host', 'port', 'encryption']"
                                     :column-label="$i18n.t('Host')"
    />

    <form-group-dead-duration namespace="dead_duration"
                              :column-label="$i18n.t('Dead duration')"
                              :text="$i18n.t('How much time in seconds should a server be marked dead before it is retried. When specifying multiple LDAP servers or a DNS name pointing to multiple IPs, then this option can be used to offer more consistent failover. A value of 0 disables this feature.')"
    />

    <form-group-connection-timeout namespace="connection_timeout"
                                   :column-label="$i18n.t('Connection timeout')"
                                   :text="$i18n.t('LDAP connection Timeout.')"
    />

    <form-group-write-timeout namespace="write_timeout"
                              :column-label="$i18n.t('Request timeout')"
                              :text="$i18n.t('LDAP request timeout.')"
    />

    <form-group-read-timeout namespace="read_timeout"
                             :column-label="$i18n.t('Response timeout')"
                             :text="$i18n.t('LDAP response timeout.')"
    />

    <form-group-base-dn namespace="basedn"
                        :column-label="$i18n.t('Base DN')"
    />

    <form-group-scope namespace="scope"
                      :column-label="$i18n.t('Scope')"
    />

    <form-group-username-attribute namespace="usernameattribute"
                                   :column-label="$i18n.t('Username Attribute')"
                                   :text="$i18n.t('Main reference attribute that contain the username.')"
    />

    <form-group-search-attributes namespace="searchattributes"
                                  :column-label="$i18n.t('Search Attributes')"
                                  :text="$i18n.t('Other attributes that can be used as the username (requires to restart the radiusd service to be effective).')"
    />

    <form-group-email-attribute namespace="email_attribute"
                                :column-label="$i18n.t('Email Attribute')"
                                :text="$i18n.t('LDAP attribute name that stores the email address against which the filter will match.')"
    />

    <form-group-bind-dn namespace="binddn"
                        :column-label="$i18n.t('Bind DN')"
                        :text="$i18n.t('Leave this field empty if you want to perform an anonymous bind.')"
    />

    <form-group-password namespace="password"
                         :column-label="$i18n.t('Password')"
    />

    <form-group-cache-match namespace="cache_match"
                            :column-label="$i18n.t('Cache match')"
                            :text="$i18n.t('Will cache results of matching a rule.')"
                            enabled-value="1"
                            disabled-value="0"
    />

    <form-group-monitor namespace="monitor"
                        :column-label="$i18n.t('Monitor')"
                        :text="$i18n.t('Do you want to monitor this source?')"
                        enabled-value="1"
                        disabled-value="0"
    />

    <form-group-shuffle namespace="shuffle"
                        :column-label="$i18n.t('Shuffle')"
                        :text="$i18n.t('Randomly choose LDAP server to query.')"
                        enabled-value="1"
                        disabled-value="0"
    />

    <form-group-use-connector namespace="use_connector"
                              :column-label="$i18n.t('Use Connector')"
                              :text="$i18n.t('Use the available PacketFence connectors to connect to this authentication source. By default, a local connector is hosted on this server.')"
                              :enabled-value="1"
                              :disabled-value="0"
    />

    <form-group-realms namespace="realms"
                       :column-label="$i18n.t('Associated Realms')"
                       :text="$i18n.t('Realms that will be associated with this source.')"
    />

    <form-group-authentication-rules namespace="authentication_rules"
                                     :column-label="$i18n.t('Authentication Rules')"
    />

    <form-group-administration-rules namespace="administration_rules"
                                     :column-label="$i18n.t('Administration Rules')"
    />
  </base-form>
</template>
<script>
import {BaseForm} from '@/components/new/'
import {
  FormGroupAdministrationRules,
  FormGroupAuthenticationRules,
  FormGroupBaseDn,
  FormGroupBindDn,
  FormGroupCacheMatch,
  FormGroupConnectionTimeout,
  FormGroupDeadDuration,
  FormGroupDescription,
  FormGroupEmailAttribute,
  FormGroupHostPortEncryption,
  FormGroupIdentifier,
  FormGroupMonitor,
  FormGroupPassword,
  FormGroupReadTimeout,
  FormGroupRealms,
  FormGroupScope,
  FormGroupSearchAttributes,
  FormGroupShuffle,
  FormGroupUseConnector,
  FormGroupUsernameAttribute,
  FormGroupWriteTimeout,
} from './'

const components = {
  BaseForm,

  FormGroupAdministrationRules,
  FormGroupAuthenticationRules,
  FormGroupBaseDn,
  FormGroupBindDn,
  FormGroupCacheMatch,
  FormGroupConnectionTimeout,
  FormGroupDeadDuration,
  FormGroupDescription,
  FormGroupEmailAttribute,
  FormGroupHostPortEncryption,
  FormGroupIdentifier,
  FormGroupMonitor,
  FormGroupPassword,
  FormGroupReadTimeout,
  FormGroupRealms,
  FormGroupScope,
  FormGroupSearchAttributes,
  FormGroupShuffle,
  FormGroupUseConnector,
  FormGroupUsernameAttribute,
  FormGroupWriteTimeout,
}

import {
  useForm as setupForm,
  useFormProps as props
} from '../_composables/useForm'
import {provide} from '@vue/composition-api';
import BaseRuleFormGroupLdapConditions
  from '@/views/Configuration/sources/_components/BaseRuleFormGroupLdapConditions';
import useLdapAttributes
  from '@/views/Configuration/sources/_components/ldapCondition/useLdapAttributes';

function setup(props) {
  const schema = setupForm(props)
  provide('conditionsComponent', BaseRuleFormGroupLdapConditions)
  useLdapAttributes(props)
  return schema
}

// @vue/component
export default {
  name: 'form-type-edir',
  inheritAttrs: false,
  components,
  props,
  setup
}
</script>
