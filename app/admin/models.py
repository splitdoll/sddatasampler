#!/usr/bin/env python
# -*- coding:utf-8 -*-


from app import db
from datetime import datetime


# 音乐风格
class Style(db.Model):
    __tablename__ = "style"
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), unique=True)
    info = db.Column(db.String(255))
    tasks = db.relationship("Task", backref="style")

    def __repr__(self):
        return "<Style %r>" % self.name


# 数据来源
class DataSource(db.Model):
    __tablename__ = "datasource"
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), unique=True)
    url = db.Column(db.String(255))
    tasks = db.relationship("Task", backref="datasource")

    def __repr__(self):
        return "<DataSource %r>" % self.name


# 年代
class Decade(db.Model):
    __tablename__ = "decade"
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), unique=True)
    tasks = db.relationship("Task", backref="decade")

    def __repr__(self):
        return "<Decade %r>" % self.name


# 采集任务
class Task(db.Model):
    __tablename__ = "task"
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), unique=True)
    style_id = db.Column(db.Integer, db.ForeignKey("style.id"))
    decade_id = db.Column(db.Integer, db.ForeignKey("decade.id"))
    datasource_id = db.Column(db.Integer, db.ForeignKey("datasource.id"))
    status = db.Column(db.String(100))
    admin_id = db.Column(db.Integer, db.ForeignKey("admin.id"))
    addtime = db.Column(db.DateTime, index=True, default=datetime.now)

    def __repr__(self):
        return "<Task %r>" % self.name


# 权限
class Auth(db.Model):
    __tablename__ = "auth"
    id = db.Column(db.Integer, primary_key=True)  # 编号
    name = db.Column(db.String(100), unique=True)  # 名称
    url = db.Column(db.String(255), unique=True)  # 地址
    addtime = db.Column(db.DateTime, index=True, default=datetime.now)  # 添加时间

    def __repr__(self):
        return "<Auth %r>" % self.name


# 角色
class Role(db.Model):
    __tablename__ = "role"
    id = db.Column(db.Integer, primary_key=True)  # 编号
    name = db.Column(db.String(100), unique=True)  # 名称
    auths = db.Column(db.String(600))  # 权限列表
    addtime = db.Column(db.DateTime, index=True, default=datetime.now)  # 添加时间
    admins = db.relationship("Admin", backref="role")  # 管理员外键关系关联

    def __repr__(self):
        return "<Role %r>" % self.name


# 管理员
class Admin(db.Model):
    __tablename__ = "admin"
    id = db.Column(db.Integer, primary_key=True)  # 编号
    name = db.Column(db.String(100), unique=True)  # 管理员账号
    pwd = db.Column(db.String(100))  # 管理员密码
    is_super = db.Column(db.SmallInteger)  # 是否为超级管理员，0为超级管理员
    role_id = db.Column(db.Integer, db.ForeignKey("role.id"))  # 所属角色
    addtime = db.Column(db.DateTime, index=True, default=datetime.now)  # 添加时间
    adminlogs = db.relationship("Adminlog", backref="admin")  # 管理员登录日志外键关系关联
    oplogs = db.relationship("Oplog", backref="admin")  # 操作日志外键关系关联
    tasks = db.relationship("Task", backref="admin") # 任务外键关系

    def __repr__(self):
        return "<Admin %r>" % self.name

    def check_pwd(self, pwd):
        from werkzeug.security import check_password_hash
        return check_password_hash(self.pwd, pwd)  # 验证密码是否正确，返回True和False


# 管理员登录日志
class Adminlog(db.Model):
    __tablename__ = "adminlog"
    id = db.Column(db.Integer, primary_key=True)  # 编号
    admin_id = db.Column(db.Integer, db.ForeignKey("admin.id"))  # 所属管理员编号
    ip = db.Column(db.String(100))  # 登录IP
    addtime = db.Column(db.DateTime, index=True, default=datetime.now)  # 登录时间

    def __repr__(self):
        return "<Adminlog %r>" % self.id


# 操作日志
class Oplog(db.Model):
    __tablename__ = "oplog"
    id = db.Column(db.Integer, primary_key=True)  # 编号
    admin_id = db.Column(db.Integer, db.ForeignKey("admin.id"))  # 所属管理员编号
    ip = db.Column(db.String(100))  # 登录IP
    reason = db.Column(db.String(600))  # 操作原因
    addtime = db.Column(db.DateTime, index=True, default=datetime.now)  # 登录时间

    def __repr__(self):
        return "<Oplog %r>" % self.id


