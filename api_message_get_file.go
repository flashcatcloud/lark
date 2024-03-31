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

// GetMessageFile 获取消息中的资源文件, 包括音频, 视频, 图片和文件, 暂不支持表情包资源下载。当前仅支持 100M 以内的资源文件的下载。
//
// 注意事项:
// - 需要开启[机器人能力](https://open.feishu.cn/document/uAjLw4CM/ugTN1YjL4UTN24CO1UjN/trouble-shooting/how-to-enable-bot-ability)
// - 机器人和消息需要在同一会话中
// - 暂不支持获取合并转发消息中的子消息的资源文件
// - 文件类型可通过 response header 中`Content-NameType`字段获取
//
// doc: https://open.feishu.cn/document/uAjLw4CM/ukTMukTMukTM/reference/im-v1/message-resource/get
// new doc: https://open.feishu.cn/document/server-docs/im-v1/message/get-2
func (r *MessageService) GetMessageFile(ctx context.Context, request *GetMessageFileReq, options ...MethodOptionFunc) (*GetMessageFileResp, *Response, error) {
	if r.cli.mock.mockMessageGetMessageFile != nil {
		r.cli.Log(ctx, LogLevelDebug, "[lark] Message#GetMessageFile mock enable")
		return r.cli.mock.mockMessageGetMessageFile(ctx, request, options...)
	}

	req := &RawRequestReq{
		Scope:                 "Message",
		API:                   "GetMessageFile",
		Method:                "GET",
		URL:                   r.cli.openBaseURL + "/open-apis/im/v1/messages/:message_id/resources/:file_key",
		Body:                  request,
		MethodOption:          newMethodOption(options),
		NeedTenantAccessToken: true,
	}
	resp := new(getMessageFileResp)

	response, err := r.cli.RawRequest(ctx, req, resp)
	return resp.Data, response, err
}

// MockMessageGetMessageFile mock MessageGetMessageFile method
func (r *Mock) MockMessageGetMessageFile(f func(ctx context.Context, request *GetMessageFileReq, options ...MethodOptionFunc) (*GetMessageFileResp, *Response, error)) {
	r.mockMessageGetMessageFile = f
}

// UnMockMessageGetMessageFile un-mock MessageGetMessageFile method
func (r *Mock) UnMockMessageGetMessageFile() {
	r.mockMessageGetMessageFile = nil
}

// GetMessageFileReq ...
type GetMessageFileReq struct {
	MessageID string `path:"message_id" json:"-"` // 待查询资源对应的消息ID, 示例值: "om_dc13264520392913993dd051dba21dcf"
	FileKey   string `path:"file_key" json:"-"`   // 待查询资源的key。可以调用[获取指定消息的内容](https://open.feishu.cn/document/uAjLw4CM/ukTMukTMukTM/reference/im-v1/message/get)接口, 通过消息ID查询消息内容中的资源Key, 注意: 请求的 file_key 和 message_id 需要匹配, 示例值: "file_456a92d6-c6ea-4de4-ac3f-7afcf44ac78g"
	Type      string `query:"type" json:"-"`      // 资源类型, 可选值有: `image`: 对应消息中的图片或富文本消息中的图片, `file`: 对应消息中的 文件、音频、视频（表情包除外）, 示例值: image
}

// getMessageFileResp ...
type getMessageFileResp struct {
	Code  int64               `json:"code,omitempty"`
	Msg   string              `json:"msg,omitempty"`
	Data  *GetMessageFileResp `json:"data,omitempty"`
	Error *ErrorDetail        `json:"error,omitempty"`
}

func (r *getMessageFileResp) SetReader(file io.Reader) {
	if r.Data == nil {
		r.Data = &GetMessageFileResp{}
	}
	r.Data.File = file
}

// GetMessageFileResp ...
type GetMessageFileResp struct {
	File io.Reader `json:"file,omitempty"`
}
