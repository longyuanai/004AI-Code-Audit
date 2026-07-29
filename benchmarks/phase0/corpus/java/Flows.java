final class Flows {
    void alternateSource() throws Exception {
        String command = System.getenv("COMMAND");
        Runtime.getRuntime().exec(command); // phase0-expect vuln
    }

    void directSource(HttpServletRequest request) throws Exception {
        String command = request.getParameter("command");
        Runtime.getRuntime().exec(command); // phase0-expect vuln
    }

    void constantSink(HttpServletRequest request) throws Exception {
        request.getParameter("ignored");
        Runtime.getRuntime().exec("echo safe"); // phase0-expect safe
    }
}
