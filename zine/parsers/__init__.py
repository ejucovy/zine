# -*- coding: utf-8 -*-
"""
    zine.parsers
    ~~~~~~~~~~~~

    This module holds the base parser informations and the dict of
    default parsers.

    :copyright: Copyright 2007 by Armin Ronacher
    :license: GNU GPL, see LICENSE for more details.
"""
from zine.application import iter_listeners, get_application


def parse(input_data, parser=None, reason='unknown', optimize=True):
    """Generate a doc tree out of the data provided. If we are not in unbound
    mode the `process-doc-tree` event is sent so that plugins can modify
    the tree in place. The reason is useful for plugins to find out if they
    want to render it or now. For example a normal blog post would have the
    reason 'post-body' or 'post-intro', an isolated page from a plugin maybe
    'page' etc.

    If optimize is enabled the return value might be a non queryable fragment.
    """
    input_data = u'\n'.join(input_data.splitlines())
    app = get_application()
    if parser is None:
        try:
            parser_cls = app.parsers[app.cfg['default_parser']]
        except KeyError:
            # the plugin that provided the default parser is not
            # longer available.  reset the config value to the builtin
            # parser and parse afterwards.
            t = app.cfg.edit()
            t.revert_to_default('default_parser')
            t.commit()
            parser_cls = SimpleHTMLParser
    else:
        try:
            parser_cls = app.parsers[parser]
        except KeyError:
            raise ValueError('parser %r does not exist' % (parser,))

    parser = parser_cls()
    tree = parser.parse(input_data, reason)

    #! allow plugins to alter the doctree.
    for callback in iter_listeners('process-doc-tree'):
        item = callback(tree, input_data, reason)
        if item is not None:
            tree = item

    if optimize:
        return tree.optimize()
    return tree


class BaseParser(object):
    """Baseclass for all kinds of parsers."""

    @staticmethod
    def get_name():
        """Return the (localized) name of the parser."""
        return self.__class__.__name__

    def parse(self, input_data, reason):
        """Return a fragment."""


from zine.parsers.simplehtml import HTMLParser, SimpleHTMLParser, \
     AutoParagraphHTMLParser
from zine.parsers.comments import CommentParser

all_parsers = {
    'plain':            HTMLParser,
    'default':          SimpleHTMLParser,
    'autop':            AutoParagraphHTMLParser,
    'comment':          CommentParser
}