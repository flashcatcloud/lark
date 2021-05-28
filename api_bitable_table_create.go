// Code generated by lark_sdk_gen. DO NOT EDIT.

package lark

import (
	"context"
)

// CreateBitableTable 新增一个数据表
//
// doc: https://open.feishu.cn/document/uAjLw4CM/ukTMukTMukTM/reference/bitable-v1/app-table/create
func (r *BitableService) CreateBitableTable(ctx context.Context, request *CreateBitableTableReq, options ...MethodOptionFunc) (*CreateBitableTableResp, *Response, error) {
	if r.cli.mock.mockBitableCreateBitableTable != nil {
		r.cli.log(ctx, LogLevelDebug, "[lark] Bitable#CreateBitableTable mock enable")
		return r.cli.mock.mockBitableCreateBitableTable(ctx, request, options...)
	}

	req := &RawRequestReq{
		Scope:               "Bitable",
		API:                 "CreateBitableTable",
		Method:              "POST",
		URL:                 "https://open.feishu.cn/open-apis/bitable/v1/apps/:app_token/tables",
		Body:                request,
		MethodOption:        newMethodOption(options),
		NeedUserAccessToken: true,
	}
	resp := new(createBitableTableResp)

	response, err := r.cli.RawRequest(ctx, req, resp)
	return resp.Data, response, err
}

func (r *Mock) MockBitableCreateBitableTable(f func(ctx context.Context, request *CreateBitableTableReq, options ...MethodOptionFunc) (*CreateBitableTableResp, *Response, error)) {
	r.mockBitableCreateBitableTable = f
}

func (r *Mock) UnMockBitableCreateBitableTable() {
	r.mockBitableCreateBitableTable = nil
}

type CreateBitableTableReq struct {
	UserIDType *IDType                     `query:"user_id_type" json:"-"` // 用户 ID 类型, 示例值："open_id", 可选值有: `open_id`：用户的 open id, `union_id`：用户的 union id, `user_id`：用户的 user id, 默认值: `open_id`, 当值为 `user_id`, 字段权限要求: 获取用户 userid
	AppToken   string                      `path:"app_token" json:"-"`     // bitable app token, 示例值："appbcbWCzen6D8dezhoCH2RpMAh"
	Table      *CreateBitableTableReqTable `json:"table,omitempty"`        // 数据表
}

type CreateBitableTableReqTable struct {
	Name *string `json:"name,omitempty"` // 数据表 名字, 示例值："table1"
}

type createBitableTableResp struct {
	Code int64                   `json:"code,omitempty"` // 错误码，非 0 表示失败
	Msg  string                  `json:"msg,omitempty"`  // 错误描述
	Data *CreateBitableTableResp `json:"data,omitempty"`
}

type CreateBitableTableResp struct {
	TableID string `json:"table_id,omitempty"` // table id
}
