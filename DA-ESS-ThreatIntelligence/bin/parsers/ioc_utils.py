
class IOCParserUtils(object):
    
    PATHSEP_NIX = '/'
    PATHSEP_WIN = '\\'
    EXTSEP = '.'
    
    @classmethod
    def parse_path(cls, unused_field_name, pathstr, prefix):
        '''Parse any of the following from an IOC:
        
            FileItem/FullPath
            ProcessItem/path
            ServiceItem/path
            ServiceItem/serviceDLL
        
        Arguments:
            unused_field_name - Required for compatibility with the parsing convention.
            pathstr - The textual value of FileItem/FullPath or FileItem/FilePath.
            mapping - A prefix for the field names to be returned by this method. 
            
        Returns:
            A dictionary of path, extension, name if found.
        '''
        head, sep, tail = pathstr.rpartition(cls.PATHSEP_NIX)
        if head == '' and sep == '' and tail == pathstr:
            # UNIX Path separator not found.
            head, sep, tail = pathstr.rpartition(cls.PATHSEP_WIN)

        ext = None
        # tail will contain the original string in the no-path-separator case.
        if cls.EXTSEP in tail:
            _, ext = tail.rsplit(cls.EXTSEP)

        # Yield the values.
        yield prefix + 'path', head or ''
        yield prefix + 'name', tail or ''
        yield prefix + 'extension', ext or ''