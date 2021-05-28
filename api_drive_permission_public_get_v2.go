// Code generated by lark_sdk_gen. DO NOT EDIT.

package lark

import (
	"context"
)

// GetDrivePublicPermissionV2 该接口用于根据 filetoken 获取文档的公共设置。
//
// doc: https://open.feishu.cn/document/ukTMukTMukTM/uITM3YjLyEzN24iMxcjN
func (r *DriveService) GetDrivePublicPermissionV2(ctx context.Context, request *GetDrivePublicPermissionV2Req, options ...MethodOptionFunc) (*GetDrivePublicPermissionV2Resp, *Response, error) {
	if r.cli.mock.mockDriveGetDrivePublicPermissionV2 != nil {
		r.cli.log(ctx, LogLevelDebug, "[lark] Drive#GetDrivePublicPermissionV2 mock enable")
		return r.cli.mock.mockDriveGetDrivePublicPermissionV2(ctx, request, options...)
	}

	req := &RawRequestReq{
		Scope:                 "Drive",
		API:                   "GetDrivePublicPermissionV2",
		Method:                "POST",
		URL:                   "https://open.feishu.cn/open-apis/drive/permission/v2/public/",
		Body:                  request,
		MethodOption:          newMethodOption(options),
		NeedTenantAccessToken: true,
		NeedUserAccessToken:   true,
	}
	resp := new(getDrivePublicPermissionV2Resp)

	response, err := r.cli.RawRequest(ctx, req, resp)
	return resp.Data, response, err
}

func (r *Mock) MockDriveGetDrivePublicPermissionV2(f func(ctx context.Context, request *GetDrivePublicPermissionV2Req, options ...MethodOptionFunc) (*GetDrivePublicPermissionV2Resp, *Response, error)) {
	r.mockDriveGetDrivePublicPermissionV2 = f
}

func (r *Mock) UnMockDriveGetDrivePublicPermissionV2() {
	r.mockDriveGetDrivePublicPermissionV2 = nil
}

type GetDrivePublicPermissionV2Req struct {
	Token string `json:"token,omitempty"` // 文件的 token，获取方式见 [对接前说明](https://open.feishu.cn/document/ukTMukTMukTM/uczNzUjL3czM14yN3MTN)的第 4 项
	Type  string `json:"type,omitempty"`  // 文档类型 "doc", "sheet" or "isv"
}

type getDrivePublicPermissionV2Resp struct {
	Code int64                           `json:"code,omitempty"`
	Msg  string                          `json:"msg,omitempty"`
	Data *GetDrivePublicPermissionV2Resp `json:"data,omitempty"`
}

type GetDrivePublicPermissionV2Resp struct {
	SecurityEntity    string `json:"security_entity,omitempty"`    // 可创建副本/打印/导出/复制设置：<br>"anyone_can_view" - 所有可访问此文档的用户<br>"anyone_can_edit" - 有编辑权限的用户
	CommentEntity     string `json:"comment_entity,omitempty"`     // 可评论设置：<br>"anyone_can_view" - 所有可访问此文档的用户<br>"anyone_can_edit" - 有编辑权限的用户
	ShareEntity       string `json:"share_entity,omitempty"`       // 谁可以添加和管理协作者：<br>"anyone"-所有可阅读或编辑此文档的用户<br>"same_tenant"-组织内所有可阅读或编辑此文档的用户<br>"only_me"-只有我可以
	LinkShareEntity   string `json:"link_share_entity,omitempty"`  // 链接共享：<br>"tenant_readable" - 组织内获得链接的人可阅读<br>"tenant_editable" - 组织内获得链接的人可编辑<br>"anyone_readable" - 获得链接的任何人可阅读<br>"anyone_editable" - 获得链接的任何人可编辑
	ExternalAccess    bool   `json:"external_access,omitempty"`    // 是否允许分享到租户外开关
	InviteExternal    bool   `json:"invite_external,omitempty"`    // 非owner是否允许邀请外部人
	PermissionVersion string `json:"permission_version,omitempty"` // 权限版本号
}
