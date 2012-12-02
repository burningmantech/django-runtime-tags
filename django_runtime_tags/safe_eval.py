""" Provides safe version of eval.
    Note that the input to this field is limited to trusted staff, so
    eval exploits are not so much a concern...
    http://code.activestate.com/recipes/364469-safe-eval/
    This file contains the modifications mentioned in the comments for
    unary '-' and bool values.
"""
import compiler
import logging

log = logging.getLogger() 

class UnsafeSourceError(Exception):
    def __init__(self,error,descr = None,node = None):
        self.error = error
        self.descr = descr
        self.node = node
        self.lineno = getattr(node,"lineno",None)
        
    def __repr__(self):
        return "UnsafeSourceError Line %d.  %s: %s" % (self.lineno, self.error, self.descr)
    __str__ = __repr__    
           
class SafeEval(object):
    
    def visit(self, node,**kw):
        cls = node.__class__
        meth = getattr(self,'visit'+cls.__name__,self.default)
        return meth(node, **kw)
            
    def default(self, node, **kw):
        for child in node.getChildNodes():
            return self.visit(child, **kw)
            
    visitExpression = default
    
    def visitConst(self, node, **kw):
        return node.value

    def visitDict(self,node,**kw):
        return dict([(self.visit(k),self.visit(v)) for k,v in node.items])
        
    def visitTuple(self,node, **kw):
        return tuple(self.visit(i) for i in node.nodes)
        
    def visitList(self,node, **kw):
        return [self.visit(i) for i in node.nodes]

    def visitUnarySub(self, node, **kw):
            return -self.visit(node.getChildNodes()[0])

class SafeEvalWithErrors(SafeEval):

    def default(self, node, **kw):
        raise UnsafeSourceError("Unsupported source construct",
                                node.__class__,node)
            
    def visitName(self,node, **kw):
        if node.name == 'True':
            return True
        elif node.name == 'False':
            return False
        raise UnsafeSourceError("Strings must be quoted", 
                                 node.name, node)
                                 
    # Add more specific errors if desired
            

def safe_eval(source, fail_on_error = True):
    walker = fail_on_error and SafeEvalWithErrors() or SafeEval()
    try:
        ast = compiler.parse(source,"eval")
    except SyntaxError, err:
        raise
    try:
        return walker.visit(ast)
    except UnsafeSourceError, err:
        raise
