#!/usr/bin/env python
# -*- coding:utf-8 -*-

from app import db, app
from app.admin import admin
from flask import render_template, redirect, url_for, flash, session, request, abort
from app.admin.forms import LoginForm, PwdForm, AuthForm, RoleForm, AdminForm, TaskForm
from app.admin.models import Admin, Oplog, Adminlog, Auth, Role, Task, DataSource, Decade, Style
from functools import wraps
import discogs_client
import os, uuid, datetime, time
from pymongo import MongoClient

page_data = None  # 存储分页数据以便返回使用
edit_role_name = None  # 存储编辑角色页的旧角色名称


# 上下文处理器（将变量直接提供给模板使用）
@admin.context_processor
def tpl_extra():
    if "admin_id" in session and Adminlog.query.filter_by(admin_id=session["admin_id"]).count() > 0:
        adminlog = Adminlog.query.filter_by(admin_id=session["admin_id"]).order_by(
            Adminlog.addtime.desc()
        ).first()
        login_time = adminlog.addtime
    else:
        # 登陆前是看不到页面的，所以给空值
        login_time = None

    data = dict(
        login_time=login_time
    )
    return data


# 定义登录判断装饰器
def admin_login_req(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # session不存在时请求登录
        if "admin" not in session:
            return redirect(url_for("admin.login", next=request.url))
        return f(*args, **kwargs)

    return decorated_function


# 定义权限控制装饰器
def admin_auth(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if "admin_id" in session:
            # 查询出权限ID，然后查出对应的路由地址
            admin = Admin.query.join(Role).filter(
                Admin.role_id == Role.id,
                Admin.id == session["admin_id"]
            ).first()
            auths = list(map(lambda v: int(v), admin.role.auths.split(",")))
            auth_list = Auth.query.all()
            urls = [v.url for v in auth_list for var in auths if var == v.id]

            # 判断是否有权限访问
            if app.config["AUTH_SWITCH"] and str(request.url_rule) is not urls:
                abort(404)
        return f(*args, **kwargs)

    return decorated_function


# 修改文件名称
def change_filename(filename):
    fileinfo = os.path.splitext(filename)  # 对名字进行前后缀分离
    filename = datetime.datetime.now().strftime("%Y%m%d%H%M%S") + "_" + uuid.uuid4().hex + fileinfo[-1]  # 生成新文件名
    return filename


# 调用蓝图（定义视图）
# 定义控制面板视图
@admin.route("/")
@admin_login_req
@admin_auth
def index():
    return render_template("index.html")


# 定义登录视图
@admin.route("/login/", methods=["GET", "POST"])
def login():
    form = LoginForm()  # 导入登录表单
    if form.validate_on_submit():  # 验证是否有提交表单
        data = form.data
        admin = Admin.query.filter_by(name=data["account"]).first()
        if not admin.check_pwd(data["pwd"]):
            flash("密码错误！", "err")
            return redirect(url_for("admin.login"))
        session["admin"] = data["account"]
        session["admin_id"] = admin.id
        adminlog = Adminlog(
            admin_id=admin.id,
            ip=request.remote_addr
        )
        db.session.add(adminlog)
        db.session.commit()
        return redirect(request.args.get("next") or url_for("admin.index"))
    return render_template("login.html", form=form)


# 定义登出视图
@admin.route("/logout/")
@admin_login_req
def logout():
    session.pop("admin")  # 移除用户session
    session.pop("admin_id")
    return redirect(url_for("admin.login"))


# 定义修改密码视图
@admin.route("/pwd/", methods=["GET", "POST"])
@admin_login_req
def pwd():
    form = PwdForm()
    if form.validate_on_submit():
        data = form.data
        admin = Admin.query.filter_by(name=session["admin"]).first()
        from werkzeug.security import generate_password_hash
        admin.pwd = generate_password_hash(data["new_pwd"])
        db.session.add(admin)
        db.session.commit()
        flash("修改密码成功，请重新登录！", "ok")
        oplog = Oplog(
            admin_id=session["admin_id"],
            ip=request.remote_addr,
            reason="修改了密码"
        )
        db.session.add(oplog)
        db.session.commit()
        return redirect(url_for("admin.logout"))
    return render_template("pwd.html", form=form)


# 定义操作日志列表视图
@admin.route("/oplog/list/<int:page>/", methods=["GET"])
@admin_login_req
@admin_auth
def oplog_list(page=None):
    global page_data
    if page is None:
        page = 1
    page_data = Oplog.query.join(Admin).filter(
        Oplog.admin_id == Admin.id
    ).order_by(
        Oplog.addtime.desc()
    ).paginate(page=page, per_page=app.config["PAGE_SET"])
    return render_template("oplog_list.html", page_data=page_data)


# 定义管理员登录日志列表视图
@admin.route("/adminloginlog/list/<int:page>/", methods=["GET"])
@admin_login_req
@admin_auth
def adminloginlog_list(page=None):
    global page_data
    if page is None:
        page = 1
    page_data = Adminlog.query.join(Admin).filter(
        Adminlog.admin_id == Admin.id
    ).order_by(
        Adminlog.addtime.desc()
    ).paginate(page=page, per_page=app.config["PAGE_SET"])
    return render_template("adminloginlog_list.html", page_data=page_data)


# 定义添加权限视图
@admin.route("/auth/add/", methods=["GET", "POST"])
@admin_login_req
@admin_auth
def auth_add():
    form = AuthForm()
    if form.validate_on_submit():
        data = form.data
        auth = Auth(
            name=data["name"],
            url=data["url"]
        )
        db.session.add(auth)
        db.session.commit()
        flash("添加权限成功！", "ok")
        oplog = Oplog(
            admin_id=session["admin_id"],
            ip=request.remote_addr,
            reason="添加新权限：%s" % data["name"]
        )
        db.session.add(oplog)
        db.session.commit()
        return redirect(url_for("admin.auth_add"))
    return render_template("auth_add.html", form=form)


# 定义编辑权限视图
@admin.route("/auth/edit/<int:id>/", methods=["GET", "POST"])
@admin_login_req
@admin_auth
def auth_edit(id=None):
    form = AuthForm()
    auth = Auth.query.get_or_404(id)
    page = page_data.page if page_data is not None else 1
    if request.method == "GET":
        form.name.data = auth.name
        form.url.data = auth.url
    if form.validate_on_submit():
        data = form.data
        oplog = Oplog(
            admin_id=session["admin_id"],
            ip=request.remote_addr,
            reason="修改权限：%s（原名：%s）" % (data["name"], auth.name)
        )
        db.session.add(oplog)
        db.session.commit()

        auth.name = data["name"]
        auth.url = data["url"]
        db.session.add(auth)
        db.session.commit()
        flash("修改权限成功！", "ok")
        return redirect(url_for("admin.auth_list", page=page))
    return render_template("auth_edit.html", form=form, page=page)


# 定义权限列表视图
@admin.route("/auth/list/<int:page>/", methods=["GET"])
@admin_login_req
@admin_auth
def auth_list(page=None):
    global page_data
    if page is None:
        page = 1
    page_data = Auth.query.order_by(
        Auth.addtime.desc()
    ).paginate(page=page, per_page=app.config["PAGE_SET"])
    return render_template("auth_list.html", page_data=page_data)


# 定义权限删除视图
@admin.route("/auth/del/<int:id>/", methods=["GET"])
@admin_login_req
@admin_auth
def auth_del(id=None):
    if page_data.pages == 1 or page_data is None:
        page = 1
    else:
        page = page_data.page if page_data.page < page_data.pages or page_data.total % page_data.per_page != 1 else page_data.pages - 1
    auth = Auth.query.filter_by(id=id).first_or_404()
    db.session.delete(auth)
    db.session.commit()
    flash("删除权限成功！", "ok")
    oplog = Oplog(
        admin_id=session["admin_id"],
        ip=request.remote_addr,
        reason="删除权限：%s" % auth.name
    )
    db.session.add(oplog)
    db.session.commit()
    return redirect(url_for("admin.auth_list", page=page))


# 定义添加角色视图
@admin.route("/role/add/", methods=["GET", "POST"])
@admin_login_req
@admin_auth
def role_add():
    form = RoleForm()
    if form.validate_on_submit():
        data = form.data
        role = Role(
            name=data["name"],
            auths=",".join(map(lambda v: str(v), data["auths"]))
        )
        db.session.add(role)
        db.session.commit()
        flash("添加角色成功！", "ok")
        oplog = Oplog(
            admin_id=session["admin_id"],
            ip=request.remote_addr,
            reason="添加新角色：%s" % data["name"]
        )
        db.session.add(oplog)
        db.session.commit()
        return redirect(url_for("admin.role_add"))
    return render_template("role_add.html", form=form)


# 定义编辑角色视图
@admin.route("/role/edit/<int:id>/", methods=["GET", "POST"])
@admin_login_req
@admin_auth
def role_edit(id=None):
    global edit_role_name
    form = RoleForm()
    role = Role.query.get_or_404(id)
    edit_role_name = role.name
    page = page_data.page if page_data is not None else 1
    if request.method == "GET":
        form.name.data = role.name
        form.auths.data = list(map(lambda v: int(v), role.auths.split(",")))
    if form.validate_on_submit():
        data = form.data
        oplog = Oplog(
            admin_id=session["admin_id"],
            ip=request.remote_addr,
            reason="修改角色：%s（原名：%s）" % (data["name"], role.name)
        )
        db.session.add(oplog)
        db.session.commit()

        role.name = data["name"]
        role.auths = ",".join(map(lambda v: str(v), data["auths"]))
        db.session.add(role)
        db.session.commit()
        flash("修改角色成功！", "ok")
        return redirect(url_for("admin.role_list", page=page))
    return render_template("role_edit.html", form=form, page=page)


# 定义角色列表视图
@admin.route("/role/list/<int:page>/", methods=["GET"])
@admin_login_req
@admin_auth
def role_list(page=None):
    global page_data
    if page is None:
        page = 1
    page_data = Role.query.order_by(
        Role.addtime.desc()
    ).paginate(page=page, per_page=app.config["PAGE_SET"])
    return render_template("role_list.html", page_data=page_data)


# 定义角色删除视图
@admin.route("/role/del/<int:id>/", methods=["GET"])
@admin_login_req
@admin_auth
def role_del(id=None):
    if page_data.pages == 1 or page_data is None:
        page = 1
    else:
        page = page_data.page if page_data.page < page_data.pages or page_data.total % page_data.per_page != 1 else page_data.pages - 1
    role = Role.query.filter_by(id=id).first_or_404()
    db.session.delete(role)
    db.session.commit()
    flash("删除角色成功！", "ok")
    oplog = Oplog(
        admin_id=session["admin_id"],
        ip=request.remote_addr,
        reason="删除角色：%s" % role.name
    )
    db.session.add(oplog)
    db.session.commit()
    return redirect(url_for("admin.role_list", page=page))


# 定义添加管理员视图
@admin.route("/admin/add/", methods=["GET", "POST"])
@admin_login_req
@admin_auth
def admin_add():
    form = AdminForm()
    if form.validate_on_submit():
        data = form.data
        from werkzeug.security import generate_password_hash
        admin = Admin(
            name=data["name"],
            pwd=generate_password_hash(data["pwd"]),
            role_id=data["role_id"],
            is_super=1
        )
        db.session.add(admin)
        db.session.commit()
        flash("添加管理员成功！", "ok")
        oplog = Oplog(
            admin_id=session["admin_id"],
            ip=request.remote_addr,
            reason="添加新管理员：%s" % data["name"]
        )
        db.session.add(oplog)
        db.session.commit()
        return redirect(url_for("admin.admin_add"))
    return render_template("admin_add.html", form=form)


# 定义管理员列表视图
@admin.route("/admin/list/<int:page>/", methods=["GET", "POST"])
@admin_login_req
@admin_auth
def admin_list(page=None):
    global page_data
    if page is None:
        page = 1
    page_data = Admin.query.join(Role).filter(
        Admin.role_id == Role.id
    ).order_by(
        Admin.addtime.desc()
    ).paginate(page=page, per_page=app.config["PAGE_SET"])
    return render_template("admin_list.html", page_data=page_data)


# 采集任务列表视图
@admin.route("/task/list/<int:page>/", methods=["GET", "POST"])
@admin_login_req
@admin_auth
def task_list(page=None):
    global page_data
    if page is None:
        page = 1
    page_data = Task.query.order_by(
        Task.addtime.desc()
    ).paginate(page=page, per_page=app.config["PAGE_SET"])
    return render_template("task_list.html", page_data=page_data)


# 定义添加采集任务视图
@admin.route("/task/add/", methods=["GET", "POST"])
@admin_login_req
@admin_auth
def task_add():
    form = TaskForm()
    if form.validate_on_submit():
        data = form.data
        addtime = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        task = Task(
            name=data["name"],
            style_id=data["style_id"],
            decade_id=data["decade_id"],
            datasource_id=data["datasource_id"],
            status="未启动",
            addtime=addtime,
            admin_id=session["admin_id"]
        )

        db.session.add(task)
        db.session.commit()
        flash("采集任务添加成功！", "ok")
        oplog = Oplog(
            admin_id=session["admin_id"],
            ip=request.remote_addr,
            reason="添加新任务：%s" % data["name"]
        )
        db.session.add(oplog)
        db.session.commit()
        return redirect(url_for("admin.task_add"))
    return render_template("task_add.html", form=form)


@admin.route("/task/del/<int:id>/", methods=["GET"])
@admin_login_req
@admin_auth
def task_del(id=None):
    if page_data.pages == 1 or page_data is None:
        page = 1
    else:
        page = page_data.page if page_data.page < page_data.pages or page_data.total % page_data.per_page != 1 else page_data.pages - 1
    task = Task.query.filter_by(id=id).first_or_404()
    db.session.delete(task)
    db.session.commit()
    flash("删除任务成功！", "ok")
    oplog = Oplog(
        admin_id=session["admin_id"],
        ip=request.remote_addr,
        reason="删除任务：%s" % task.name
    )
    db.session.add(oplog)
    db.session.commit()
    return redirect(url_for("admin.task_list", page=page))


@admin.route("/task/start/<int:id>/", methods=["GET"])
@admin_login_req
@admin_auth
def task_start(id=None):
    if page_data.pages == 1 or page_data is None:
        page = 1
    else:
        page = page_data.page if page_data.page < page_data.pages or page_data.total % page_data.per_page != 1 else page_data.pages - 1

    task = Task.query.get_or_404(id)
    decade = task.decade.name
    style = task.style.name
    datasource = task.datasource.name

    if datasource == "discogs":
        # mongo init
        client = MongoClient("localhost", 27017)
        mondb = client.anon_traveler
        user_token = "vqJpOnpnunvjmTohXEVBJLtWbMUMyUePwQSYtxwa"
        user_agent = "anontraveler.com/2.0"
        discogsclient = discogs_client.Client(user_agent, user_token=user_token)
        type = "master"
        format = "album"
        for year in range(int(decade), int(decade)+9):
            spider_process_discogs = mondb.spider_process_discogs.find_one({"style": style, "year": year})
            if (spider_process_discogs and spider_process_discogs["finished"] == 1):
                continue

            search_results = discogsclient.search(type=type, year=year, style=style, format=format)
            time.sleep(1)

            if search_results.count <= 0:
                if (spider_process_discogs):
                    mondb.spider_process_discogs.update_one({"style": style, "year": year}, {
                        "$set": {"count": search_results.count, "pages": search_results.pages, "page_now": 0,
                                 "finished": 1}})
                else:
                    mondb.spider_process_discogs.insert(
                        {"style": style, "year": year, "count": search_results.count, "pages": search_results.pages,
                         "page_now": 0, "finished": 1})
                continue

            if (spider_process_discogs):
                mondb.spider_process_discogs.update_one({"style": style, "year": year}, {
                    "$set": {"count": search_results.count, "pages": search_results.pages, "finished": 0}})
            else:
                mondb.spider_process_discogs.insert(
                    {"style": style, "year": year, "count": search_results.count, "pages": search_results.pages,
                     "page_now": 0, "finished": 0})
                spider_process_discogs = {"style": style, "year": year, "count": search_results.count,
                                          "pages": search_results.pages, "page_now": 0, "finished": 0}

            page_count = search_results.pages

            for page_now in range(spider_process_discogs["page_now"], page_count):
                list_results = search_results.page(page_now)
                for master in list_results:
                    result_detail = discogsclient.master(master.id)
                    if not mondb.orig_data_album_discogs.find_one({"id": master.id}):
                        time.sleep(1)
                        print(result_detail.title)
                        mondb.orig_data_album_discogs.insert(result_detail.data)

                mondb.spider_process_discogs.update_one({"style": style, "year": year}, {"$set": {"page_now": page_now}})

            mondb.spider_process_discogs.update_one({"style": style, "year": year}, {"$set": {"finished": 1}})

    return redirect(url_for("admin.task_list", page=page))


@admin.route("/task/stop/<int:id>/", methods=["GET"])
@admin_login_req
@admin_auth
def task_stop(id=None):
    pass