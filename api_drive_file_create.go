// Code generated by lark_sdk_gen. DO NOT EDIT.

package lark

import (
	"context"
)

// CreateDriveFile
//
// 该接口用于根据 folderToken 创建 Doc或 Sheet 。
// 若没有特定的文件夹用于承载创建的文档，可以先调用「获取文件夹元信息」文档中的「获取 root folder (我的空间) meta」接口，获得我的空间的 token，然后再使用此接口。创建的文档将会在「我的空间」的「归我所有」列表里。
// 该接口不支持并发创建，且调用频率上限为 5QPS 且 10000次每天
//
// doc: https://open.feishu.cn/document/ukTMukTMukTM/uQTNzUjL0UzM14CN1MTN
func (r *DriveService) CreateDriveFile(ctx context.Context, request *CreateDriveFileReq, options ...MethodOptionFunc) (*CreateDriveFileResp, *Response, error) {
	if r.cli.mock.mockDriveCreateDriveFile != nil {
		r.cli.log(ctx, LogLevelDebug, "[lark] Drive#CreateDriveFile mock enable")
		return r.cli.mock.mockDriveCreateDriveFile(ctx, request, options...)
	}

	req := &RawRequestReq{
		Scope:                 "Drive",
		API:                   "CreateDriveFile",
		Method:                "POST",
		URL:                   "https://open.feishu.cn/open-apis/drive/explorer/v2/file/:folderToken",
		Body:                  request,
		MethodOption:          newMethodOption(options),
		NeedTenantAccessToken: true,
		NeedUserAccessToken:   true,
	}
	resp := new(createDriveFileResp)

	response, err := r.cli.RawRequest(ctx, req, resp)
	return resp.Data, response, err
}

func (r *Mock) MockDriveCreateDriveFile(f func(ctx context.Context, request *CreateDriveFileReq, options ...MethodOptionFunc) (*CreateDriveFileResp, *Response, error)) {
	r.mockDriveCreateDriveFile = f
}

func (r *Mock) UnMockDriveCreateDriveFile() {
	r.mockDriveCreateDriveFile = nil
}

type CreateDriveFileReq struct {
	FolderToken string `path:"folderToken" json:"-"` // 文件夹 token，用于在此文件夹下新建文档，获取方式见[概述](https://open.feishu.cn/document/ukTMukTMukTM/uUDN04SN0QjL1QDN/files/guide/introduction)
	Title       string `json:"title,omitempty"`      // 创建文档的标题
	Type        string `json:"type,omitempty"`       // 需要创建文档的类型  "doc" 、 "sheet"  or  "bitable"
}

type createDriveFileResp struct {
	Code int64                `json:"code,omitempty"`
	Msg  string               `json:"msg,omitempty"`
	Data *CreateDriveFileResp `json:"data,omitempty"`
}

type CreateDriveFileResp struct {
	URL      string `json:"url,omitempty"`      // 新创建文档的 url
	Revision int64  `json:"revision,omitempty"` // 新创建文档的版本号
}
