#!/usr/bin/env python
# -*- coding:utf-8 -*-

from flask_migrate import Migrate, MigrateCommand
from flask_script import Manager, Shell, Server
from app import app, db

manager = Manager(app)
migrate = Migrate(app, db)


@manager.shell
def make_shell_context():
    return dict(app=app, db=db)


manager.add_command("shell", Shell(make_context=make_shell_context))
manager.add_command("db", MigrateCommand)
manager.add_command("runserver", Server(use_debugger=True))


if __name__ == "__main__":
    manager.run()
