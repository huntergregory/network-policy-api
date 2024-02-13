//go:build !ignore_autogenerated

/*
Copyright The Kubernetes Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

// Code generated by controller-gen. DO NOT EDIT.

package v1alpha1

import (
	"k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
)

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *AdminNetworkPolicy) DeepCopyInto(out *AdminNetworkPolicy) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ObjectMeta.DeepCopyInto(&out.ObjectMeta)
	in.Spec.DeepCopyInto(&out.Spec)
	in.Status.DeepCopyInto(&out.Status)
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new AdminNetworkPolicy.
func (in *AdminNetworkPolicy) DeepCopy() *AdminNetworkPolicy {
	if in == nil {
		return nil
	}
	out := new(AdminNetworkPolicy)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyObject is an autogenerated deepcopy function, copying the receiver, creating a new runtime.Object.
func (in *AdminNetworkPolicy) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *AdminNetworkPolicyEgressPeer) DeepCopyInto(out *AdminNetworkPolicyEgressPeer) {
	*out = *in
	if in.Namespaces != nil {
		in, out := &in.Namespaces, &out.Namespaces
		*out = new(NamespacedPeer)
		(*in).DeepCopyInto(*out)
	}
	if in.Pods != nil {
		in, out := &in.Pods, &out.Pods
		*out = new(NamespacedPodPeer)
		(*in).DeepCopyInto(*out)
	}
	if in.Nodes != nil {
		in, out := &in.Nodes, &out.Nodes
		*out = new(v1.LabelSelector)
		(*in).DeepCopyInto(*out)
	}
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new AdminNetworkPolicyEgressPeer.
func (in *AdminNetworkPolicyEgressPeer) DeepCopy() *AdminNetworkPolicyEgressPeer {
	if in == nil {
		return nil
	}
	out := new(AdminNetworkPolicyEgressPeer)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *AdminNetworkPolicyEgressRule) DeepCopyInto(out *AdminNetworkPolicyEgressRule) {
	*out = *in
	if in.To != nil {
		in, out := &in.To, &out.To
		*out = make([]AdminNetworkPolicyEgressPeer, len(*in))
		for i := range *in {
			(*in)[i].DeepCopyInto(&(*out)[i])
		}
	}
	if in.Ports != nil {
		in, out := &in.Ports, &out.Ports
		*out = new([]AdminNetworkPolicyPort)
		if **in != nil {
			in, out := *in, *out
			*out = make([]AdminNetworkPolicyPort, len(*in))
			for i := range *in {
				(*in)[i].DeepCopyInto(&(*out)[i])
			}
		}
	}
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new AdminNetworkPolicyEgressRule.
func (in *AdminNetworkPolicyEgressRule) DeepCopy() *AdminNetworkPolicyEgressRule {
	if in == nil {
		return nil
	}
	out := new(AdminNetworkPolicyEgressRule)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *AdminNetworkPolicyIngressPeer) DeepCopyInto(out *AdminNetworkPolicyIngressPeer) {
	*out = *in
	if in.Namespaces != nil {
		in, out := &in.Namespaces, &out.Namespaces
		*out = new(NamespacedPeer)
		(*in).DeepCopyInto(*out)
	}
	if in.Pods != nil {
		in, out := &in.Pods, &out.Pods
		*out = new(NamespacedPodPeer)
		(*in).DeepCopyInto(*out)
	}
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new AdminNetworkPolicyIngressPeer.
func (in *AdminNetworkPolicyIngressPeer) DeepCopy() *AdminNetworkPolicyIngressPeer {
	if in == nil {
		return nil
	}
	out := new(AdminNetworkPolicyIngressPeer)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *AdminNetworkPolicyIngressRule) DeepCopyInto(out *AdminNetworkPolicyIngressRule) {
	*out = *in
	if in.From != nil {
		in, out := &in.From, &out.From
		*out = make([]AdminNetworkPolicyIngressPeer, len(*in))
		for i := range *in {
			(*in)[i].DeepCopyInto(&(*out)[i])
		}
	}
	if in.Ports != nil {
		in, out := &in.Ports, &out.Ports
		*out = new([]AdminNetworkPolicyPort)
		if **in != nil {
			in, out := *in, *out
			*out = make([]AdminNetworkPolicyPort, len(*in))
			for i := range *in {
				(*in)[i].DeepCopyInto(&(*out)[i])
			}
		}
	}
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new AdminNetworkPolicyIngressRule.
func (in *AdminNetworkPolicyIngressRule) DeepCopy() *AdminNetworkPolicyIngressRule {
	if in == nil {
		return nil
	}
	out := new(AdminNetworkPolicyIngressRule)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *AdminNetworkPolicyList) DeepCopyInto(out *AdminNetworkPolicyList) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ListMeta.DeepCopyInto(&out.ListMeta)
	if in.Items != nil {
		in, out := &in.Items, &out.Items
		*out = make([]AdminNetworkPolicy, len(*in))
		for i := range *in {
			(*in)[i].DeepCopyInto(&(*out)[i])
		}
	}
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new AdminNetworkPolicyList.
func (in *AdminNetworkPolicyList) DeepCopy() *AdminNetworkPolicyList {
	if in == nil {
		return nil
	}
	out := new(AdminNetworkPolicyList)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyObject is an autogenerated deepcopy function, copying the receiver, creating a new runtime.Object.
func (in *AdminNetworkPolicyList) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *AdminNetworkPolicyPort) DeepCopyInto(out *AdminNetworkPolicyPort) {
	*out = *in
	if in.PortNumber != nil {
		in, out := &in.PortNumber, &out.PortNumber
		*out = new(Port)
		**out = **in
	}
	if in.NamedPort != nil {
		in, out := &in.NamedPort, &out.NamedPort
		*out = new(string)
		**out = **in
	}
	if in.PortRange != nil {
		in, out := &in.PortRange, &out.PortRange
		*out = new(PortRange)
		**out = **in
	}
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new AdminNetworkPolicyPort.
func (in *AdminNetworkPolicyPort) DeepCopy() *AdminNetworkPolicyPort {
	if in == nil {
		return nil
	}
	out := new(AdminNetworkPolicyPort)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *AdminNetworkPolicySpec) DeepCopyInto(out *AdminNetworkPolicySpec) {
	*out = *in
	in.Subject.DeepCopyInto(&out.Subject)
	if in.Ingress != nil {
		in, out := &in.Ingress, &out.Ingress
		*out = make([]AdminNetworkPolicyIngressRule, len(*in))
		for i := range *in {
			(*in)[i].DeepCopyInto(&(*out)[i])
		}
	}
	if in.Egress != nil {
		in, out := &in.Egress, &out.Egress
		*out = make([]AdminNetworkPolicyEgressRule, len(*in))
		for i := range *in {
			(*in)[i].DeepCopyInto(&(*out)[i])
		}
	}
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new AdminNetworkPolicySpec.
func (in *AdminNetworkPolicySpec) DeepCopy() *AdminNetworkPolicySpec {
	if in == nil {
		return nil
	}
	out := new(AdminNetworkPolicySpec)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *AdminNetworkPolicyStatus) DeepCopyInto(out *AdminNetworkPolicyStatus) {
	*out = *in
	if in.Conditions != nil {
		in, out := &in.Conditions, &out.Conditions
		*out = make([]v1.Condition, len(*in))
		for i := range *in {
			(*in)[i].DeepCopyInto(&(*out)[i])
		}
	}
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new AdminNetworkPolicyStatus.
func (in *AdminNetworkPolicyStatus) DeepCopy() *AdminNetworkPolicyStatus {
	if in == nil {
		return nil
	}
	out := new(AdminNetworkPolicyStatus)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *AdminNetworkPolicySubject) DeepCopyInto(out *AdminNetworkPolicySubject) {
	*out = *in
	if in.Namespaces != nil {
		in, out := &in.Namespaces, &out.Namespaces
		*out = new(v1.LabelSelector)
		(*in).DeepCopyInto(*out)
	}
	if in.Pods != nil {
		in, out := &in.Pods, &out.Pods
		*out = new(NamespacedPodSubject)
		(*in).DeepCopyInto(*out)
	}
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new AdminNetworkPolicySubject.
func (in *AdminNetworkPolicySubject) DeepCopy() *AdminNetworkPolicySubject {
	if in == nil {
		return nil
	}
	out := new(AdminNetworkPolicySubject)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *BaselineAdminNetworkPolicy) DeepCopyInto(out *BaselineAdminNetworkPolicy) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ObjectMeta.DeepCopyInto(&out.ObjectMeta)
	in.Spec.DeepCopyInto(&out.Spec)
	in.Status.DeepCopyInto(&out.Status)
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new BaselineAdminNetworkPolicy.
func (in *BaselineAdminNetworkPolicy) DeepCopy() *BaselineAdminNetworkPolicy {
	if in == nil {
		return nil
	}
	out := new(BaselineAdminNetworkPolicy)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyObject is an autogenerated deepcopy function, copying the receiver, creating a new runtime.Object.
func (in *BaselineAdminNetworkPolicy) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *BaselineAdminNetworkPolicyEgressRule) DeepCopyInto(out *BaselineAdminNetworkPolicyEgressRule) {
	*out = *in
	if in.To != nil {
		in, out := &in.To, &out.To
		*out = make([]AdminNetworkPolicyEgressPeer, len(*in))
		for i := range *in {
			(*in)[i].DeepCopyInto(&(*out)[i])
		}
	}
	if in.Ports != nil {
		in, out := &in.Ports, &out.Ports
		*out = new([]AdminNetworkPolicyPort)
		if **in != nil {
			in, out := *in, *out
			*out = make([]AdminNetworkPolicyPort, len(*in))
			for i := range *in {
				(*in)[i].DeepCopyInto(&(*out)[i])
			}
		}
	}
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new BaselineAdminNetworkPolicyEgressRule.
func (in *BaselineAdminNetworkPolicyEgressRule) DeepCopy() *BaselineAdminNetworkPolicyEgressRule {
	if in == nil {
		return nil
	}
	out := new(BaselineAdminNetworkPolicyEgressRule)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *BaselineAdminNetworkPolicyIngressRule) DeepCopyInto(out *BaselineAdminNetworkPolicyIngressRule) {
	*out = *in
	if in.From != nil {
		in, out := &in.From, &out.From
		*out = make([]AdminNetworkPolicyIngressPeer, len(*in))
		for i := range *in {
			(*in)[i].DeepCopyInto(&(*out)[i])
		}
	}
	if in.Ports != nil {
		in, out := &in.Ports, &out.Ports
		*out = new([]AdminNetworkPolicyPort)
		if **in != nil {
			in, out := *in, *out
			*out = make([]AdminNetworkPolicyPort, len(*in))
			for i := range *in {
				(*in)[i].DeepCopyInto(&(*out)[i])
			}
		}
	}
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new BaselineAdminNetworkPolicyIngressRule.
func (in *BaselineAdminNetworkPolicyIngressRule) DeepCopy() *BaselineAdminNetworkPolicyIngressRule {
	if in == nil {
		return nil
	}
	out := new(BaselineAdminNetworkPolicyIngressRule)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *BaselineAdminNetworkPolicyList) DeepCopyInto(out *BaselineAdminNetworkPolicyList) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ListMeta.DeepCopyInto(&out.ListMeta)
	if in.Items != nil {
		in, out := &in.Items, &out.Items
		*out = make([]BaselineAdminNetworkPolicy, len(*in))
		for i := range *in {
			(*in)[i].DeepCopyInto(&(*out)[i])
		}
	}
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new BaselineAdminNetworkPolicyList.
func (in *BaselineAdminNetworkPolicyList) DeepCopy() *BaselineAdminNetworkPolicyList {
	if in == nil {
		return nil
	}
	out := new(BaselineAdminNetworkPolicyList)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyObject is an autogenerated deepcopy function, copying the receiver, creating a new runtime.Object.
func (in *BaselineAdminNetworkPolicyList) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *BaselineAdminNetworkPolicySpec) DeepCopyInto(out *BaselineAdminNetworkPolicySpec) {
	*out = *in
	in.Subject.DeepCopyInto(&out.Subject)
	if in.Ingress != nil {
		in, out := &in.Ingress, &out.Ingress
		*out = make([]BaselineAdminNetworkPolicyIngressRule, len(*in))
		for i := range *in {
			(*in)[i].DeepCopyInto(&(*out)[i])
		}
	}
	if in.Egress != nil {
		in, out := &in.Egress, &out.Egress
		*out = make([]BaselineAdminNetworkPolicyEgressRule, len(*in))
		for i := range *in {
			(*in)[i].DeepCopyInto(&(*out)[i])
		}
	}
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new BaselineAdminNetworkPolicySpec.
func (in *BaselineAdminNetworkPolicySpec) DeepCopy() *BaselineAdminNetworkPolicySpec {
	if in == nil {
		return nil
	}
	out := new(BaselineAdminNetworkPolicySpec)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *BaselineAdminNetworkPolicyStatus) DeepCopyInto(out *BaselineAdminNetworkPolicyStatus) {
	*out = *in
	if in.Conditions != nil {
		in, out := &in.Conditions, &out.Conditions
		*out = make([]v1.Condition, len(*in))
		for i := range *in {
			(*in)[i].DeepCopyInto(&(*out)[i])
		}
	}
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new BaselineAdminNetworkPolicyStatus.
func (in *BaselineAdminNetworkPolicyStatus) DeepCopy() *BaselineAdminNetworkPolicyStatus {
	if in == nil {
		return nil
	}
	out := new(BaselineAdminNetworkPolicyStatus)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *NamespacedPeer) DeepCopyInto(out *NamespacedPeer) {
	*out = *in
	if in.NamespaceSelector != nil {
		in, out := &in.NamespaceSelector, &out.NamespaceSelector
		*out = new(v1.LabelSelector)
		(*in).DeepCopyInto(*out)
	}
	if in.SameLabels != nil {
		in, out := &in.SameLabels, &out.SameLabels
		*out = make([]string, len(*in))
		copy(*out, *in)
	}
	if in.NotSameLabels != nil {
		in, out := &in.NotSameLabels, &out.NotSameLabels
		*out = make([]string, len(*in))
		copy(*out, *in)
	}
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new NamespacedPeer.
func (in *NamespacedPeer) DeepCopy() *NamespacedPeer {
	if in == nil {
		return nil
	}
	out := new(NamespacedPeer)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *NamespacedPodPeer) DeepCopyInto(out *NamespacedPodPeer) {
	*out = *in
	in.Namespaces.DeepCopyInto(&out.Namespaces)
	in.PodSelector.DeepCopyInto(&out.PodSelector)
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new NamespacedPodPeer.
func (in *NamespacedPodPeer) DeepCopy() *NamespacedPodPeer {
	if in == nil {
		return nil
	}
	out := new(NamespacedPodPeer)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *NamespacedPodSubject) DeepCopyInto(out *NamespacedPodSubject) {
	*out = *in
	in.NamespaceSelector.DeepCopyInto(&out.NamespaceSelector)
	in.PodSelector.DeepCopyInto(&out.PodSelector)
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new NamespacedPodSubject.
func (in *NamespacedPodSubject) DeepCopy() *NamespacedPodSubject {
	if in == nil {
		return nil
	}
	out := new(NamespacedPodSubject)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *Port) DeepCopyInto(out *Port) {
	*out = *in
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new Port.
func (in *Port) DeepCopy() *Port {
	if in == nil {
		return nil
	}
	out := new(Port)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *PortRange) DeepCopyInto(out *PortRange) {
	*out = *in
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new PortRange.
func (in *PortRange) DeepCopy() *PortRange {
	if in == nil {
		return nil
	}
	out := new(PortRange)
	in.DeepCopyInto(out)
	return out
}
