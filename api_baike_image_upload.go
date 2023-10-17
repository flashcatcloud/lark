// Code generated by lark_sdk_gen. DO NOT EDIT.
/**
 * Copyright 2022 chyroc
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package lark

import (
	"context"
	"io"
)

// UploadBaikeImage 词条图片资源上传。
//
// 为了更好地提升接口文档的的易理解性, 我们对文档进行了升级, 请尽快迁移至[新版本>>](https://open.feishu.cn/document/uAjLw4CM/ukTMukTMukTM/lingo-v1/file/upload)
//
// doc: https://open.feishu.cn/document/uAjLw4CM/ukTMukTMukTM/reference/baike-v1/file/upload
// new doc: https://open.feishu.cn/document/server-docs/baike-v1/file/upload
//
// Deprecated
func (r *BaikeService) UploadBaikeImage(ctx context.Context, request *UploadBaikeImageReq, options ...MethodOptionFunc) (*UploadBaikeImageResp, *Response, error) {
	if r.cli.mock.mockBaikeUploadBaikeImage != nil {
		r.cli.log(ctx, LogLevelDebug, "[lark] Baike#UploadBaikeImage mock enable")
		return r.cli.mock.mockBaikeUploadBaikeImage(ctx, request, options...)
	}

	req := &RawRequestReq{
		Scope:                 "Baike",
		API:                   "UploadBaikeImage",
		Method:                "POST",
		URL:                   r.cli.openBaseURL + "/open-apis/baike/v1/files/upload",
		Body:                  request,
		MethodOption:          newMethodOption(options),
		NeedTenantAccessToken: true,
		NeedUserAccessToken:   true,
		IsFile:                true,
	}
	resp := new(uploadBaikeImageResp)

	response, err := r.cli.RawRequest(ctx, req, resp)
	return resp.Data, response, err
}

// MockBaikeUploadBaikeImage mock BaikeUploadBaikeImage method
func (r *Mock) MockBaikeUploadBaikeImage(f func(ctx context.Context, request *UploadBaikeImageReq, options ...MethodOptionFunc) (*UploadBaikeImageResp, *Response, error)) {
	r.mockBaikeUploadBaikeImage = f
}

// UnMockBaikeUploadBaikeImage un-mock BaikeUploadBaikeImage method
func (r *Mock) UnMockBaikeUploadBaikeImage() {
	r.mockBaikeUploadBaikeImage = nil
}

// UploadBaikeImageReq ...
type UploadBaikeImageReq struct {
	Name string    `json:"name,omitempty"` // 文件名称, 当前仅支持上传图片且图片格式为以下六种: icon、bmp、gif、png、jpeg、webp, 示例值: "示例图片.png", 长度范围: `1` ～ `100` 字符
	File io.Reader `json:"file,omitempty"` // 二进制文件内容, 高宽像素在 320-4096 像素之间, 大小在 3KB-10MB 的图片, 示例值: file binary
}

// UploadBaikeImageResp ...
type UploadBaikeImageResp struct {
	FileToken string `json:"file_token,omitempty"` // 文件 token
}

// uploadBaikeImageResp ...
type uploadBaikeImageResp struct {
	Code int64                 `json:"code,omitempty"` // 错误码, 非 0 表示失败
	Msg  string                `json:"msg,omitempty"`  // 错误描述
	Data *UploadBaikeImageResp `json:"data,omitempty"`
}
