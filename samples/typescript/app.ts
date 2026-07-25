function render(req: Request): unknown {
  const expression = req.query.expression;
  return eval(expression);
}

class Controller {}
