// Code generated by lark_sdk_gen. DO NOT EDIT.

package lark

import (
	"context"
)

// GetDriveDocMeta 该接口用于根据 docToken 获取元数据。
//
// doc: https://open.feishu.cn/document/ukTMukTMukTM/uczN3UjL3czN14yN3cTN
func (r *DriveService) GetDriveDocMeta(ctx context.Context, request *GetDriveDocMetaReq, options ...MethodOptionFunc) (*GetDriveDocMetaResp, *Response, error) {
	if r.cli.mock.mockDriveGetDriveDocMeta != nil {
		r.cli.log(ctx, LogLevelDebug, "[lark] Drive#GetDriveDocMeta mock enable")
		return r.cli.mock.mockDriveGetDriveDocMeta(ctx, request, options...)
	}

	req := &RawRequestReq{
		Scope:                 "Drive",
		API:                   "GetDriveDocMeta",
		Method:                "GET",
		URL:                   "https://open.feishu.cn/open-apis/doc/v2/meta/:docToken",
		Body:                  request,
		MethodOption:          newMethodOption(options),
		NeedTenantAccessToken: true,
		NeedUserAccessToken:   true,
	}
	resp := new(getDriveDocMetaResp)

	response, err := r.cli.RawRequest(ctx, req, resp)
	return resp.Data, response, err
}

func (r *Mock) MockDriveGetDriveDocMeta(f func(ctx context.Context, request *GetDriveDocMetaReq, options ...MethodOptionFunc) (*GetDriveDocMetaResp, *Response, error)) {
	r.mockDriveGetDriveDocMeta = f
}

func (r *Mock) UnMockDriveGetDriveDocMeta() {
	r.mockDriveGetDriveDocMeta = nil
}

type GetDriveDocMetaReq struct {
	DocToken string `path:"docToken" json:"-"` // doc 的 token，获取方式见[准备接入文档 API](https://open.feishu.cn/document/ukTMukTMukTM/ugzNzUjL4czM14CO3MTN/guide/getting-start)
}

type getDriveDocMetaResp struct {
	Code int64                `json:"code,omitempty"`
	Msg  string               `json:"msg,omitempty"`
	Data *GetDriveDocMetaResp `json:"data,omitempty"`
}

type GetDriveDocMetaResp struct {
	CreateDate     string `json:"create_date,omitempty"`      // 创建日期
	CreateTime     int64  `json:"create_time,omitempty"`      // 创建时间戳
	Creator        string `json:"creator,omitempty"`          // 创建者open_id
	CreateUserName string `json:"create_user_name,omitempty"` // 创建者用户名
	DeleteFlag     int64  `json:"delete_flag,omitempty"`      // 删除标志，0表示正常访问未删除，1表示在回收站，2表示已经彻底删除
	EditTime       int64  `json:"edit_time,omitempty"`        // 最后编辑时间戳
	EditUserName   string `json:"edit_user_name,omitempty"`   // 最后编辑者用户名
	IsExternal     bool   `json:"is_external,omitempty"`      // 是否外部文档
	IsPined        bool   `json:"is_pined,omitempty"`         // 是否在接口调用者目录里快速访问
	IsStared       bool   `json:"is_stared,omitempty"`        // 是否在接口调用者目录里收藏
	ObjType        string `json:"obj_type,omitempty"`         // 文档类型，固定是doc
	Owner          string `json:"owner,omitempty"`            // 当前所有者open_id
	OwnerUserName  string `json:"owner_user_name,omitempty"`  // 当前所有者用户名
	ServerTime     int64  `json:"server_time,omitempty"`      // 处理请求时的服务器时间戳
	TenantID       string `json:"tenant_id,omitempty"`        // 文档所在租户id
	Title          string `json:"title,omitempty"`            // 文档名称
	Type           int64  `json:"type,omitempty"`             // 文档类型，固定是2
	URL            string `json:"url,omitempty"`              // 文档url
}
