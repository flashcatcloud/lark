// Code generated by lark_sdk_gen. DO NOT EDIT.

package lark

import (
	"context"
)

// GetHireNoteList 获取备注列表
//
// doc: https://open.feishu.cn/document/ukTMukTMukTM/uMzM1YjLzMTN24yMzUjN/hire-v1/note/list
func (r *HireService) GetHireNoteList(ctx context.Context, request *GetHireNoteListReq, options ...MethodOptionFunc) (*GetHireNoteListResp, *Response, error) {
	if r.cli.mock.mockHireGetHireNoteList != nil {
		r.cli.log(ctx, LogLevelDebug, "[lark] Hire#GetHireNoteList mock enable")
		return r.cli.mock.mockHireGetHireNoteList(ctx, request, options...)
	}

	req := &RawRequestReq{
		Scope:                 "Hire",
		API:                   "GetHireNoteList",
		Method:                "GET",
		URL:                   "https://open.feishu.cn/open-apis/hire/v1/notes",
		Body:                  request,
		MethodOption:          newMethodOption(options),
		NeedTenantAccessToken: true,
	}
	resp := new(getHireNoteListResp)

	response, err := r.cli.RawRequest(ctx, req, resp)
	return resp.Data, response, err
}

func (r *Mock) MockHireGetHireNoteList(f func(ctx context.Context, request *GetHireNoteListReq, options ...MethodOptionFunc) (*GetHireNoteListResp, *Response, error)) {
	r.mockHireGetHireNoteList = f
}

func (r *Mock) UnMockHireGetHireNoteList() {
	r.mockHireGetHireNoteList = nil
}

type GetHireNoteListReq struct {
	PageSize   *int64  `query:"page_size" json:"-"`    // 每页限制, 每页最大不超过100, 示例值：10
	PageToken  *string `query:"page_token" json:"-"`   // 查询游标, 由上一页结果返回, 第一页不传, 示例值："1"
	TalentID   string  `query:"talent_id" json:"-"`    // 人才ID, 示例值："6916472453069883661"
	UserIDType *IDType `query:"user_id_type" json:"-"` // 用户 ID 类型, 示例值："open_id", 可选值有: `open_id`：用户的 open id, `union_id`：用户的 union id, `user_id`：用户的 user id, 默认值: `open_id`, 当值为 `user_id`, 字段权限要求: 获取用户 userid
}

type getHireNoteListResp struct {
	Code int64                `json:"code,omitempty"` // 错误码，非 0 表示失败
	Msg  string               `json:"msg,omitempty"`  // 错误描述
	Data *GetHireNoteListResp `json:"data,omitempty"`
}

type GetHireNoteListResp struct {
	Items     []*GetHireNoteListRespItem `json:"items,omitempty"`      // 备注数据列表
	HasMore   bool                       `json:"has_more,omitempty"`   // 是否还有下一页数据
	PageToken string                     `json:"page_token,omitempty"` // 游标, 翻下一页数据时使用
}

type GetHireNoteListRespItem struct {
	ID            string `json:"id,omitempty"`             // ID备注
	TalentID      string `json:"talent_id,omitempty"`      // 人才ID
	ApplicationID string `json:"application_id,omitempty"` // 投递ID
	IsPrivate     bool   `json:"is_private,omitempty"`     // 是否私密
	CreateTime    int64  `json:"create_time,omitempty"`    // 创建时间
	ModifyTime    int64  `json:"modify_time,omitempty"`    // 更新时间
	CreatorID     string `json:"creator_id,omitempty"`     // 创建人ID
	Content       string `json:"content,omitempty"`        // 内容
}
