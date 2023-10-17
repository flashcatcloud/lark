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
)

// GetBaikeEntity 通过词条 id 拉取对应的词条详情信息。
//
// 为了更好地提升接口文档的的易理解性, 我们对文档进行了升级, 请尽快迁移至[新版本>>](https://open.feishu.cn/document/uAjLw4CM/ukTMukTMukTM/lingo-v1/entity/get)
// 也支持通过 provider 和 outer_id 返回对应实体的详情数据。此时路径中的 entity_id 为固定的 enterprise_0
//
// doc: https://open.feishu.cn/document/uAjLw4CM/ukTMukTMukTM/reference/baike-v1/entity/get
// new doc: https://open.feishu.cn/document/server-docs/baike-v1/entity/get
//
// Deprecated
func (r *BaikeService) GetBaikeEntity(ctx context.Context, request *GetBaikeEntityReq, options ...MethodOptionFunc) (*GetBaikeEntityResp, *Response, error) {
	if r.cli.mock.mockBaikeGetBaikeEntity != nil {
		r.cli.log(ctx, LogLevelDebug, "[lark] Baike#GetBaikeEntity mock enable")
		return r.cli.mock.mockBaikeGetBaikeEntity(ctx, request, options...)
	}

	req := &RawRequestReq{
		Scope:                 "Baike",
		API:                   "GetBaikeEntity",
		Method:                "GET",
		URL:                   r.cli.openBaseURL + "/open-apis/baike/v1/entities/:entity_id",
		Body:                  request,
		MethodOption:          newMethodOption(options),
		NeedTenantAccessToken: true,
		NeedUserAccessToken:   true,
	}
	resp := new(getBaikeEntityResp)

	response, err := r.cli.RawRequest(ctx, req, resp)
	return resp.Data, response, err
}

// MockBaikeGetBaikeEntity mock BaikeGetBaikeEntity method
func (r *Mock) MockBaikeGetBaikeEntity(f func(ctx context.Context, request *GetBaikeEntityReq, options ...MethodOptionFunc) (*GetBaikeEntityResp, *Response, error)) {
	r.mockBaikeGetBaikeEntity = f
}

// UnMockBaikeGetBaikeEntity un-mock BaikeGetBaikeEntity method
func (r *Mock) UnMockBaikeGetBaikeEntity() {
	r.mockBaikeGetBaikeEntity = nil
}

// GetBaikeEntityReq ...
type GetBaikeEntityReq struct {
	EntityID   string  `path:"entity_id" json:"-"`     // 词条 ID, 示例值: "enterprise_515879"
	Provider   *string `query:"provider" json:"-"`     // 外部系统, 示例值: 星云, 长度范围: `2` ～ `32` 字符
	OuterID    *string `query:"outer_id" json:"-"`     // 词条在外部系统中对应的唯一 ID, 示例值: 12345, 长度范围: `1` ～ `64` 字符
	UserIDType *IDType `query:"user_id_type" json:"-"` // 用户 ID 类型, 示例值: open_id, 可选值有: open_id: 标识一个用户在某个应用中的身份。同一个用户在不同应用中的 Open ID 不同。[了解更多: 如何获取 Open ID](https://open.feishu.cn/document/uAjLw4CM/ugTN1YjL4UTN24CO1UjN/trouble-shooting/how-to-obtain-openid), union_id: 标识一个用户在某个应用开发商下的身份。同一用户在同一开发商下的应用中的 Union ID 是相同的, 在不同开发商下的应用中的 Union ID 是不同的。通过 Union ID, 应用开发商可以把同个用户在多个应用中的身份关联起来。[了解更多: 如何获取 Union ID？](https://open.feishu.cn/document/uAjLw4CM/ugTN1YjL4UTN24CO1UjN/trouble-shooting/how-to-obtain-union-id), user_id: 标识一个用户在某个租户内的身份。同一个用户在租户 A 和租户 B 内的 User ID 是不同的。在同一个租户内, 一个用户的 User ID 在所有应用（包括商店应用）中都保持一致。User ID 主要用于在不同的应用间打通用户数据。[了解更多: 如何获取 User ID？](https://open.feishu.cn/document/uAjLw4CM/ugTN1YjL4UTN24CO1UjN/trouble-shooting/how-to-obtain-user-id), 默认值: `open_id`, 当值为 `user_id`, 字段权限要求: 获取用户 user ID
}

// GetBaikeEntityResp ...
type GetBaikeEntityResp struct {
	Entity *GetBaikeEntityRespEntity `json:"entity,omitempty"` // 词条
}

// GetBaikeEntityRespEntity ...
type GetBaikeEntityRespEntity struct {
	ID          string                               `json:"id,omitempty"`           // 词条 ID （需要更新某个词条时填写, 若是创建新词条可不填写）
	MainKeys    []*GetBaikeEntityRespEntityMainKey   `json:"main_keys,omitempty"`    // 词条名
	Aliases     []*GetBaikeEntityRespEntityAliase    `json:"aliases,omitempty"`      // 别名
	Description string                               `json:"description,omitempty"`  // 纯文本格式词条释义。注: description 和 rich_text 至少有一个, 否则会报错: 1540001
	CreateTime  string                               `json:"create_time,omitempty"`  // 词条创建时间
	UpdateTime  string                               `json:"update_time,omitempty"`  // 词条最近更新时间
	RelatedMeta *GetBaikeEntityRespEntityRelatedMeta `json:"related_meta,omitempty"` // 更多相关信息
	Statistics  *GetBaikeEntityRespEntityStatistics  `json:"statistics,omitempty"`   // 当前词条收到的反馈数据
	OuterInfo   *GetBaikeEntityRespEntityOuterInfo   `json:"outer_info,omitempty"`   // 外部系统关联数据
	RichText    string                               `json:"rich_text,omitempty"`    // 富文本格式（当填写富文本内容时, description字段将会失效可不填写）, 支持的格式参考[飞书词典指南](https://open.feishu.cn/document/uAjLw4CM/ukTMukTMukTM/reference/baike-v1/overview)中的释义部分
}

// GetBaikeEntityRespEntityAliase ...
type GetBaikeEntityRespEntityAliase struct {
	Key           string                                       `json:"key,omitempty"`            // 名称的值
	DisplayStatus *GetBaikeEntityRespEntityAliaseDisplayStatus `json:"display_status,omitempty"` // 名称展示范围
}

// GetBaikeEntityRespEntityAliaseDisplayStatus ...
type GetBaikeEntityRespEntityAliaseDisplayStatus struct {
	AllowHighlight bool `json:"allow_highlight,omitempty"` // 对应名称是否在消息/云文档高亮
	AllowSearch    bool `json:"allow_search,omitempty"`    // 对应名称是否在搜索结果中展示
}

// GetBaikeEntityRespEntityMainKey ...
type GetBaikeEntityRespEntityMainKey struct {
	Key           string                                        `json:"key,omitempty"`            // 名称的值
	DisplayStatus *GetBaikeEntityRespEntityMainKeyDisplayStatus `json:"display_status,omitempty"` // 名称展示范围
}

// GetBaikeEntityRespEntityMainKeyDisplayStatus ...
type GetBaikeEntityRespEntityMainKeyDisplayStatus struct {
	AllowHighlight bool `json:"allow_highlight,omitempty"` // 对应名称是否在消息/云文档高亮
	AllowSearch    bool `json:"allow_search,omitempty"`    // 对应名称是否在搜索结果中展示
}

// GetBaikeEntityRespEntityOuterInfo ...
type GetBaikeEntityRespEntityOuterInfo struct {
	Provider string `json:"provider,omitempty"` // 外部系统（不能包含中横线 "-"）
	OuterID  string `json:"outer_id,omitempty"` // 词条在外部系统中对应的唯一 ID（不能包含中横线 "-"）
}

// GetBaikeEntityRespEntityRelatedMeta ...
type GetBaikeEntityRespEntityRelatedMeta struct {
	Users           []*GetBaikeEntityRespEntityRelatedMetaUser           `json:"users,omitempty"`           // 相关联系人
	Chats           []*GetBaikeEntityRespEntityRelatedMetaChat           `json:"chats,omitempty"`           // 相关服务中的相关公开群
	Docs            []*GetBaikeEntityRespEntityRelatedMetaDoc            `json:"docs,omitempty"`            // 相关云文档
	Oncalls         []*GetBaikeEntityRespEntityRelatedMetaOncall         `json:"oncalls,omitempty"`         // 相关服务中的相关值班号
	Links           []*GetBaikeEntityRespEntityRelatedMetaLink           `json:"links,omitempty"`           // 相关链接
	Abbreviations   []*GetBaikeEntityRespEntityRelatedMetaAbbreviation   `json:"abbreviations,omitempty"`   // 相关词条
	Classifications []*GetBaikeEntityRespEntityRelatedMetaClassification `json:"classifications,omitempty"` // 当前词条所属分类, 词条只能属于二级分类, 且每个一级分类下只能选择一个二级分类。
	Images          []*GetBaikeEntityRespEntityRelatedMetaImage          `json:"images,omitempty"`          // 上传的图片
}

// GetBaikeEntityRespEntityRelatedMetaAbbreviation ...
type GetBaikeEntityRespEntityRelatedMetaAbbreviation struct {
	ID string `json:"id,omitempty"` // 相关词条 ID
}

// GetBaikeEntityRespEntityRelatedMetaChat ...
type GetBaikeEntityRespEntityRelatedMetaChat struct {
	ID    string `json:"id,omitempty"`    // 对应相关信息 ID
	Title string `json:"title,omitempty"` // 对应相关信息的描述, 如相关联系人的描述、相关链接的标题
	URL   string `json:"url,omitempty"`   // 链接地址
}

// GetBaikeEntityRespEntityRelatedMetaClassification ...
type GetBaikeEntityRespEntityRelatedMetaClassification struct {
	ID       string `json:"id,omitempty"`        // 二级分类 ID
	Name     string `json:"name,omitempty"`      // 二级分类名称
	FatherID string `json:"father_id,omitempty"` // 对应一级分类 ID
}

// GetBaikeEntityRespEntityRelatedMetaDoc ...
type GetBaikeEntityRespEntityRelatedMetaDoc struct {
	Title string `json:"title,omitempty"` // 对应相关信息的描述, 如相关联系人的描述、相关链接的标题
	URL   string `json:"url,omitempty"`   // 链接地址
}

// GetBaikeEntityRespEntityRelatedMetaImage ...
type GetBaikeEntityRespEntityRelatedMetaImage struct {
	Token string `json:"token,omitempty"` // 通过文件接口上传图片后, 获得的图片 token
}

// GetBaikeEntityRespEntityRelatedMetaLink ...
type GetBaikeEntityRespEntityRelatedMetaLink struct {
	Title string `json:"title,omitempty"` // 对应相关信息的描述, 如相关联系人的描述、相关链接的标题
	URL   string `json:"url,omitempty"`   // 链接地址
}

// GetBaikeEntityRespEntityRelatedMetaOncall ...
type GetBaikeEntityRespEntityRelatedMetaOncall struct {
	ID    string `json:"id,omitempty"`    // 对应相关信息 ID
	Title string `json:"title,omitempty"` // 对应相关信息的描述, 如相关联系人的描述、相关链接的标题
	URL   string `json:"url,omitempty"`   // 链接地址
}

// GetBaikeEntityRespEntityRelatedMetaUser ...
type GetBaikeEntityRespEntityRelatedMetaUser struct {
	ID    string `json:"id,omitempty"`    // 对应相关信息 ID
	Title string `json:"title,omitempty"` // 对应相关信息的描述, 如相关联系人的描述、相关链接的标题
	URL   string `json:"url,omitempty"`   // 链接地址
}

// GetBaikeEntityRespEntityStatistics ...
type GetBaikeEntityRespEntityStatistics struct {
	LikeCount    int64 `json:"like_count,omitempty"`    // 累计点赞
	DislikeCount int64 `json:"dislike_count,omitempty"` // 当前词条版本收到的负反馈数量
}

// getBaikeEntityResp ...
type getBaikeEntityResp struct {
	Code int64               `json:"code,omitempty"` // 错误码, 非 0 表示失败
	Msg  string              `json:"msg,omitempty"`  // 错误描述
	Data *GetBaikeEntityResp `json:"data,omitempty"`
}
