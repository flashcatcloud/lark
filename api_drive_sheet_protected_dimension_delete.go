// Code generated by lark_sdk_gen. DO NOT EDIT.

package lark

import (
	"context"
)

// DeleteSheetProtectedDimension 该接口用于根据保护范围ID删除保护范围，最多支持同时删除10个ID。
//
// doc: https://open.feishu.cn/document/ukTMukTMukTM/uYTM5YjL2ETO24iNxkjN
func (r *DriveService) DeleteSheetProtectedDimension(ctx context.Context, request *DeleteSheetProtectedDimensionReq, options ...MethodOptionFunc) (*DeleteSheetProtectedDimensionResp, *Response, error) {
	if r.cli.mock.mockDriveDeleteSheetProtectedDimension != nil {
		r.cli.log(ctx, LogLevelDebug, "[lark] Drive#DeleteSheetProtectedDimension mock enable")
		return r.cli.mock.mockDriveDeleteSheetProtectedDimension(ctx, request, options...)
	}

	req := &RawRequestReq{
		Scope:                 "Drive",
		API:                   "DeleteSheetProtectedDimension",
		Method:                "DELETE",
		URL:                   "https://open.feishu.cn/open-apis/sheets/v2/spreadsheets/:spreadsheetToken/protected_range_batch_del",
		Body:                  request,
		MethodOption:          newMethodOption(options),
		NeedTenantAccessToken: true,
		NeedUserAccessToken:   true,
	}
	resp := new(deleteSheetProtectedDimensionResp)

	response, err := r.cli.RawRequest(ctx, req, resp)
	return resp.Data, response, err
}

func (r *Mock) MockDriveDeleteSheetProtectedDimension(f func(ctx context.Context, request *DeleteSheetProtectedDimensionReq, options ...MethodOptionFunc) (*DeleteSheetProtectedDimensionResp, *Response, error)) {
	r.mockDriveDeleteSheetProtectedDimension = f
}

func (r *Mock) UnMockDriveDeleteSheetProtectedDimension() {
	r.mockDriveDeleteSheetProtectedDimension = nil
}

type DeleteSheetProtectedDimensionReq struct {
	SpreadSheetToken string   `path:"spreadsheetToken" json:"-"` // sheet 的 token，获取方式见[在线表格开发指南](https://open.feishu.cn/document/ukTMukTMukTM/uATMzUjLwEzM14CMxMTN/overview)
	ProtectIDs       []string `json:"protectIds,omitempty"`      // 需要删除的保护范围ID，可以通过[获取表格元数据](https://open.feishu.cn/document/ukTMukTMukTM/uETMzUjLxEzM14SMxMTN)接口获取
}

type deleteSheetProtectedDimensionResp struct {
	Code int64                              `json:"code,omitempty"`
	Msg  string                             `json:"msg,omitempty"`
	Data *DeleteSheetProtectedDimensionResp `json:"data,omitempty"`
}

type DeleteSheetProtectedDimensionResp struct {
	DelProtectIDs []string `json:"delProtectIds,omitempty"` // 成功删除的保护范围ID
}
