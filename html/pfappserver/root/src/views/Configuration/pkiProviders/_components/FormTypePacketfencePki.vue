<template>
  <base-form
    :form="form"
    :meta="meta"
    :schema="schema"
    :isLoading="isLoading"
  >
    <form-group-identifier namespace="id"
                           :column-label="$i18n.t('PKI Provider Name')"
                           :disabled="!isNew && !isClone"
    />

    <form-group-profile namespace="profile"
                        :column-label="$i18n.t('Template')"
                        :text="$i18n.t('Template used for the generation of certificate.')"
    />

    <form-group-country namespace="country"
                        :column-label="$i18n.t('Country')"
                        :text="$i18n.t('Country for the certificate.')"
    />

    <form-group-state namespace="state"
                      :column-label="$i18n.t('State')"
                      :text="$i18n.t('State for the certificate.')"
    />

    <form-group-street-address namespace="streetaddress"
                               :column-label="$i18n.t('Street Address')"
                               :text="$i18n.t('Street address for the certificate.')"
    />

    <form-group-postal-code namespace="postalcode"
                            :column-label="$i18n.t('Postal Code')"
                            :text="$i18n.t('Postal Code for the certificate.')"
    />

    <form-group-locality namespace="locality"
                         :column-label="$i18n.t('Locality')"
                         :text="$i18n.t('Locality for the certificate.')"
    />

    <form-group-organization namespace="organization"
                             :column-label="$i18n.t('Organization')"
                             :text="$i18n.t('Organization for the certificate.')"
    />

    <form-group-common-name-attribute namespace="cn_attribute"
                                      :column-label="$i18n.t('Common Name Attribute')"
                                      :text="$i18n.t('Defines what attribute of the node to use as the common name during the certificate generation.')"
    />

    <form-group-common-name-format namespace="cn_format"
                                   :column-label="$i18n.t('Common Name Format')"
                                   :text="$i18n.t('Defines how the common name will be formated. %s will expand to the defined Common Name Attribute value.')"
    />

    <form-group-revoke-on-registration namespace="revoke_on_unregistration"
                                       :column-label="$i18n.t('Revoke on unregistration')"
                                       :text="$i18n.t('Enable to revoke the certificate when the node using it is unregistered. Do not use if multiple devices share the same certificate.')"
                                       enabled-value="Y"
                                       disabled-value="N"
    />

    <form-group-certificate-validity-time-from-unreg-date namespace="certificate_validity_time_from_unreg_date"
                                       :column-label="$i18n.t('Set the certificate validity date to the unreg date value')"
                                       :text="$i18n.t('Enable to apply the same expiration date of the certificate as the unregistration date of the node.')"
                                       enabled-value="Y"
                                       disabled-value="N"
    />

    <form-group-ca-cert-path namespace="ca_cert_path"
                             :column-label="$i18n.t('CA certificate file')"
                             :title="$i18n.t('Upload CA certificate file')"
                             :text="$i18n.t('CA certificate used to generate client certificate/key combination.')"
    />

    <form-group-server-cert-path namespace="server_cert_path"
                                 :column-label="$i18n.t('Server certificate file')"
                                 :title="$i18n.t('Upload server certificate file')"
                                 :text="$i18n.t('RADIUS server authentication certificate.')"
    />
  </base-form>
</template>
<script>
import {BaseForm} from '@/components/new/'
import {
  FormGroupCaCertPath,
  FormGroupCommonNameAttribute,
  FormGroupCommonNameFormat,
  FormGroupCountry,
  FormGroupIdentifier,
  FormGroupLocality,
  FormGroupOrganization,
  FormGroupPostalCode,
  FormGroupProfile,
  FormGroupRevokeOnRegistration,
  FormGroupCertificateValidityTimeFromUnregDate,
  FormGroupServerCertPath,
  FormGroupState,
  FormGroupStreetAddress
} from './'
import {useForm as setup, useFormProps as props} from '../_composables/useForm'

const components = {
  BaseForm,

  FormGroupCaCertPath,
  FormGroupCommonNameAttribute,
  FormGroupCommonNameFormat,
  FormGroupCountry,
  FormGroupIdentifier,
  FormGroupLocality,
  FormGroupOrganization,
  FormGroupPostalCode,
  FormGroupProfile,
  FormGroupRevokeOnRegistration,
  FormGroupCertificateValidityTimeFromUnregDate,
  FormGroupServerCertPath,
  FormGroupState,
  FormGroupStreetAddress
}

// @vue/component
export default {
  name: 'form-type-packetfence-local',
  inheritAttrs: false,
  components,
  props,
  setup
}
</script>
