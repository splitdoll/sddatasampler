#!/usr/bin/env python
# -*- coding:utf-8 -*-

from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, FileField, TextAreaField, SelectField, SelectMultipleField
from wtforms.validators import DataRequired, ValidationError, EqualTo
from app.admin.models import Admin, Auth, Role, Style, DataSource, Decade


class LoginForm(FlaskForm):
    """管理员登录表单"""
    account = StringField(
        label="账号",
        validators=[
            DataRequired("请输入账号！")
        ],
        description="账号",
        render_kw={  # 附加选项
            "class": "form-control",
            "placeholder": "请输入账号！",
            # "required": "required"  # 添加强制属性，H5会在前端验证
        }
    )
    pwd = PasswordField(
        label="密码",
        validators=[
            DataRequired("请输入密码！")
        ],
        description="密码",
        render_kw={
            "class": "form-control",
            "placeholder": "请输入密码！",
            # "required": "required"
        }
    )
    submit = SubmitField(
        "登录",
        render_kw={
            "class": "btn btn-primary btn-block btn-flat"
        }
    )

    # 账号验证
    def validate_account(self, field):
        account = field.data
        admin = Admin.query.filter_by(name=account).count()
        if admin == 0:
            raise ValidationError("账号不存在！")


class PwdForm(FlaskForm):
    """修改密码"""
    old_pwd = PasswordField(
        label="旧密码",
        validators=[
            DataRequired("请输入旧密码！")
        ],
        description="旧密码",
        render_kw={
            "class": "form-control",
            "autofocus": "",
            "placeholder": "请输入旧密码！"
        }
    )
    new_pwd = PasswordField(
        label="新密码",
        validators=[
            DataRequired("请输入新密码！")
        ],
        description="新密码",
        render_kw={
            "class": "form-control",
            "placeholder": "请输入新密码！"
        }
    )
    submit = SubmitField(
        "提交",
        render_kw={
            "class": "btn btn-primary"
        }
    )

    # 旧密码验证
    def validate_old_pwd(self, field):
        from flask import session
        old_pwd = field.data
        name = session["admin"]
        admin = Admin.query.filter_by(name=name).first()
        if not admin.check_pwd(old_pwd):
            raise ValidationError("旧密码错误！")


class TaskForm(FlaskForm):
    """任务表单"""
    name = StringField(
        label="任务名称",
        validators=[
            DataRequired("请输入任务名称！")
        ],
        description="任务名称",
        render_kw={
            "class": "form-control",
            "id": "input_name",
            "autofocus": "",
            "placeholder": "请输入任务名称！"
        }
    )
    style_id = SelectField(
        label="风格",
        validators=[
            DataRequired("请选择风格！")
        ],
        coerce=int,
        choices=[(0, "未选择")] + [(v.id, v.name) for v in Style.query.all()],
        description="风格",
        render_kw={
            "class": "form-control",
            "id": "input_style_id"
        }
    )
    decade_id = SelectField(
        label="年代",
        validators=[
            DataRequired("请选择年代！")
        ],
        coerce=int,
        choices=[(0, "未选择")] + [(v.id, v.name) for v in Decade.query.all()],
        description="年代",
        render_kw={
            "class": "form-control",
            "id": "input_decade_id"
        }
    )
    datasource_id = SelectField(
        label="数据来源",
        validators=[
            DataRequired("请选择数据来源！")
        ],
        coerce=int,
        choices=[(0, "未选择")] + [(v.id, v.name) for v in DataSource.query.all()],
        description="数据来源",
        render_kw={
            "class": "form-control",
            "id": "input_datasource_id"
        }
    )
    submit = SubmitField(
        "提交",
        render_kw={
            "class": "btn btn-primary"
        }
    )

    def validate_name(self, field):
        auth = Auth.query.filter_by(name=field.data).count()
        if auth == 1:
            raise ValidationError("名称已经存在！")


class AuthForm(FlaskForm):
    """权限表单"""
    name = StringField(
        label="权限名称",
        validators=[
            DataRequired("请输入权限名称！")
        ],
        description="权限名称",
        render_kw={
            "class": "form-control",
            "id": "input_name",
            "autofocus": "",
            "placeholder": "请输入权限名称！"
        }
    )
    url = StringField(
        label="权限地址",
        validators=[
            DataRequired("请输入权限地址！")
        ],
        description="权限地址",
        render_kw={
            "class": "form-control",
            "id": "input_url",
            "placeholder": "请输入权限地址！"
        }
    )
    submit = SubmitField(
        "提交",
        render_kw={
            "class": "btn btn-primary"
        }
    )

    def validate_name(self, field):
        auth = Auth.query.filter_by(name=field.data).count()
        if auth == 1:
            raise ValidationError("名称已经存在！")

    def validate_url(self, field):
        auth = Auth.query.filter_by(url=field.data).count()
        if auth == 1:
            raise ValidationError("地址已经存在！")


class RoleForm(FlaskForm):
    """角色表单"""
    name = StringField(
        label="角色名称",
        validators=[
            DataRequired("请输入角色名称！")
        ],
        description="角色名称",
        render_kw={
            "class": "form-control",
            "id": "input_name",
            "autofocus": "",
            "placeholder": "请输入角色名称！"
        }
    )
    auths = SelectMultipleField(
        label="权限列表",
        validators=[
            DataRequired("请选择操作权限！")
        ],
        coerce=int,
        choices=[(v.id, v.name) for v in Auth.query.all()],
        description="权限列表",
        render_kw={
            "class": "form-control"
        }
    )
    submit = SubmitField(
        "提交",
        render_kw={
            "class": "btn btn-primary"
        }
    )

    def validate_name(self, field):
        if Role.query.filter_by(name=field.data).count() == 1:
            from app.admin.views import edit_role_name
            if edit_role_name != field.data:
                raise ValidationError("名称已经存在！")


class AdminForm(FlaskForm):
    """管理员表单"""
    name = StringField(
        label="管理员名称",
        validators=[
            DataRequired("请输入管理员名称！")
        ],
        description="管理员名称",
        render_kw={  # 附加选项
            "class": "form-control",
            "autofocus": "",
            "placeholder": "请输入账号！"
        }
    )
    pwd = PasswordField(
        label="管理员密码",
        validators=[
            DataRequired("请输入管理员密码！")
        ],
        description="管理员密码",
        render_kw={
            "class": "form-control",
            "placeholder": "请输入管理员密码！"
        }
    )
    re_pwd = PasswordField(
        label="管理员重复密码",
        validators=[
            DataRequired("请再次输入管理员密码！"),
            EqualTo("pwd", message="两次密码输入不一致！")
        ],
        description="管理员重复密码",
        render_kw={
            "class": "form-control",
            "placeholder": "请再次输入管理员密码！"
        }
    )
    role_id = SelectField(
        label="所属角色",
        validators=[
            DataRequired("请选择所属角色！")
        ],
        coerce=int,
        choices=[(0, "未选择")] + [(v.id, v.name) for v in Role.query.all()],
        description="所属角色",
        render_kw={
            "class": "form-control",
            "id": "input_role_id"
        }
    )
    submit = SubmitField(
        "提交",
        render_kw={
            "class": "btn btn-primary"
        }
    )

    def validate_name(self, field):
        auth = Admin.query.filter_by(name=field.data).count()
        if auth == 1:
            raise ValidationError("管理员名称已经存在！")
