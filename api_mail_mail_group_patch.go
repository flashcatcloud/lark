// Code generated by lark_sdk_gen. DO NOT EDIT.

package lark

import (
	"context"
)

// UpdateMailGroupPatch 更新邮件组部分字段，没有填写的字段不会被更新
//
// doc: https://open.feishu.cn/document/uAjLw4CM/ukTMukTMukTM/reference/mail-v1/mailgroup/patch
func (r *MailService) UpdateMailGroupPatch(ctx context.Context, request *UpdateMailGroupPatchReq, options ...MethodOptionFunc) (*UpdateMailGroupPatchResp, *Response, error) {
	if r.cli.mock.mockMailUpdateMailGroupPatch != nil {
		r.cli.log(ctx, LogLevelDebug, "[lark] Mail#UpdateMailGroupPatch mock enable")
		return r.cli.mock.mockMailUpdateMailGroupPatch(ctx, request, options...)
	}

	req := &RawRequestReq{
		Scope:                 "Mail",
		API:                   "UpdateMailGroupPatch",
		Method:                "PATCH",
		URL:                   "https://open.feishu.cn/open-apis/mail/v1/mailgroups/:mailgroup_id",
		Body:                  request,
		MethodOption:          newMethodOption(options),
		NeedTenantAccessToken: true,
	}
	resp := new(updateMailGroupPatchResp)

	response, err := r.cli.RawRequest(ctx, req, resp)
	return resp.Data, response, err
}

func (r *Mock) MockMailUpdateMailGroupPatch(f func(ctx context.Context, request *UpdateMailGroupPatchReq, options ...MethodOptionFunc) (*UpdateMailGroupPatchResp, *Response, error)) {
	r.mockMailUpdateMailGroupPatch = f
}

func (r *Mock) UnMockMailUpdateMailGroupPatch() {
	r.mockMailUpdateMailGroupPatch = nil
}

type UpdateMailGroupPatchReq struct {
	MailGroupID    string  `path:"mailgroup_id" json:"-"`       // 邮件组ID或者邮件组地址, 示例值："xxxxxxxxxxxxxxx 或 test_mail_group@xxx.xx"
	Name           *string `json:"name,omitempty"`              // 邮件组名称, 示例值："test mail group"
	Description    *string `json:"description,omitempty"`       // 邮件组描述, 示例值："mail group for testing"
	WhoCanSendMail *string `json:"who_can_send_mail,omitempty"` // 谁可发送邮件到此邮件组, 示例值："ALL_INTERNAL_USERS", 可选值有: `ANYONE`：任何人, `ALL_INTERNAL_USERS`：仅组织内部成员, `ALL_GROUP_MEMBERS`：仅邮件组成员, `CUSTOM_MEMBERS`：自定义成员
}

type updateMailGroupPatchResp struct {
	Code int64                     `json:"code,omitempty"` // 错误码，非 0 表示失败
	Msg  string                    `json:"msg,omitempty"`  // 错误描述
	Data *UpdateMailGroupPatchResp `json:"data,omitempty"`
}

type UpdateMailGroupPatchResp struct {
	MailGroupID             string `json:"mailgroup_id,omitempty"`               // 邮件组ID
	Email                   string `json:"email,omitempty"`                      // 邮件组地址
	Name                    string `json:"name,omitempty"`                       // 邮件组名称
	Description             string `json:"description,omitempty"`                // 邮件组描述
	DirectMembersCount      string `json:"direct_members_count,omitempty"`       // 邮件组成员数量
	IncludeExternalMember   bool   `json:"include_external_member,omitempty"`    // 是否包含外部成员
	IncludeAllCompanyMember bool   `json:"include_all_company_member,omitempty"` // 是否是全员邮件组
	WhoCanSendMail          string `json:"who_can_send_mail,omitempty"`          // 谁可发送邮件到此邮件组, 可选值有: `ANYONE`：任何人, `ALL_INTERNAL_USERS`：仅组织内部成员, `ALL_GROUP_MEMBERS`：仅邮件组成员, `CUSTOM_MEMBERS`：自定义成员
}
