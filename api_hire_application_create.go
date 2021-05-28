// Code generated by lark_sdk_gen. DO NOT EDIT.

package lark

import (
	"context"
)

// CreateHireApplication 根据人才 ID 和职位 ID 创建投递
//
// doc: https://open.feishu.cn/document/ukTMukTMukTM/uMzM1YjLzMTN24yMzUjN/hire-v1/application/create
func (r *HireService) CreateHireApplication(ctx context.Context, request *CreateHireApplicationReq, options ...MethodOptionFunc) (*CreateHireApplicationResp, *Response, error) {
	if r.cli.mock.mockHireCreateHireApplication != nil {
		r.cli.log(ctx, LogLevelDebug, "[lark] Hire#CreateHireApplication mock enable")
		return r.cli.mock.mockHireCreateHireApplication(ctx, request, options...)
	}

	req := &RawRequestReq{
		Scope:                 "Hire",
		API:                   "CreateHireApplication",
		Method:                "POST",
		URL:                   "https://open.feishu.cn/open-apis/hire/v1/applications",
		Body:                  request,
		MethodOption:          newMethodOption(options),
		NeedTenantAccessToken: true,
	}
	resp := new(createHireApplicationResp)

	response, err := r.cli.RawRequest(ctx, req, resp)
	return resp.Data, response, err
}

func (r *Mock) MockHireCreateHireApplication(f func(ctx context.Context, request *CreateHireApplicationReq, options ...MethodOptionFunc) (*CreateHireApplicationResp, *Response, error)) {
	r.mockHireCreateHireApplication = f
}

func (r *Mock) UnMockHireCreateHireApplication() {
	r.mockHireCreateHireApplication = nil
}

type CreateHireApplicationReq struct {
	TalentID string `json:"talent_id,omitempty"` // 人才ID, 示例值："12312312312"
	JobID    string `json:"job_id,omitempty"`    // 职位ID, 示例值："12312312312"
}

type createHireApplicationResp struct {
	Code int64                      `json:"code,omitempty"` // 错误码，非 0 表示失败
	Msg  string                     `json:"msg,omitempty"`  // 错误描述
	Data *CreateHireApplicationResp `json:"data,omitempty"`
}

type CreateHireApplicationResp struct {
	ID string `json:"id,omitempty"` // 投递ID
}
