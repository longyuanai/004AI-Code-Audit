class Demo {
    void find(HttpServletRequest request, Statement statement)
            throws Exception {
        String owner = request.getParameter("owner");
        statement.executeQuery(
                "SELECT * FROM reports WHERE owner='" + owner + "'");
    }
}
