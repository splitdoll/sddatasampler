#!/usr/bin/env python
# -*- coding:utf-8 -*-

from flask import Flask, render_template
from flask_sqlalchemy import SQLAlchemy
from flask_mongoengine import MongoEngine
import pymysql
import os

app = Flask(__name__)

app.config["SQLALCHEMY_DATABASE_URI"] = "mysql+pymysql://root:23916593@127.0.0.1:3306/sddbdemo"  # 定义Mysql数据库连接
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = True
app.config["SECRET_KEY"] = "6a8312d499ed42828bb85fefac3607b7"  # CSRF保护设置密钥
app.config["UP_DIR"] = os.path.join(os.path.abspath(os.path.dirname(__file__)),
                                    "static" + os.sep + "uploads" + os.sep) # 配置文件上传目录
app.config["PAGE_SET"] = 10 # 分页数上限
app.config["AUTH_SWITCH"] = False # 页面访问权限开关，True为开启
app.debug = False

db = SQLAlchemy(app)

# 注册蓝图

from app.admin import admin as admin_blueprint

app.register_blueprint(admin_blueprint)

