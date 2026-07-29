function alternateSource(): unknown {
  const expression = process.env.EXPRESSION;
  return eval(expression); // phase0-expect vuln
}

function directSource(request: Request): unknown {
  const expression = request.query.expression;
  return eval(expression); // phase0-expect vuln
}

function constantSink(request: Request): unknown {
  request.query.ignored;
  return eval("2 + 2"); // phase0-expect safe
}
