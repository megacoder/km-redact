#!/usr/bin/env python
# vim: noet sw=4 ts=4

import	sys
import	os
import	argparse
import	re

try:
	from version import Verstion
except:
	Version = '0.0.0rc0'

class	KmRedact( object ):

	def	__init__( self ):
		self._init_ip_hiding()
		self._init_dns_hiding()
		self._init_port_hiding()
		pass

	def	main( self ):
		retval = 1
		while True:
			prog = os.path.splitext(
				os.path.basename( sys.argv[ 0 ] )
			)[ 0 ]
			if prog == '__init__':
				prog = 'km-redact'
			p = argparse.ArgumentParser(
				prog        = prog,
				description = '''Obscure sensitive HIPPA in text.''',
				epilog      = '''Gosh, that was great!'''
			)
			p.add_argument(
				'-D',
				'--keep-dns',
				dest   = 'keep_dns',
				action = 'store_true',
				help   = 'do not obscure DNS names',
			)
			p.add_argument(
				'-I',
				'--keep-ip',
				dest    = 'keep_ip',
				action  = 'store_true',
				help    = 'do not obscure IP addresses',
			)
			p.add_argument(
				'-p',
				'--port',
				dest   = 'keep_ports',
				action = 'store_true',
				help   = 'do not obscure port numbers',
			)
			p.add_argument(
				'-r',
				'--ring',
				dest   = 'want_decoder_ring',
				action = 'store_true',
				help   = 'show magic decoder ring',
			)
			p.add_argument(
				'--version',
				action = 'version',
				version = Version,
				help = '{0} Version {1}'.format(
					prog,
					Version
				)
			)
			default = []
			p.add_argument(
				'names',
				nargs   = '*',
				metavar = 'FILE',
				default = default,
				help    = 'files to process if not stdin',
			)
			self.opts = p.parse_args()
			if len( self.opts.names ) == 0:
				self.process()
			else:
				for name in self.opts.names:
					with open( name ) as f:
						self.process( f )
			retval = 0
			break
		return retval

	def	process( self, f = sys.stdin ):
		for line in f:
			line = line.rstrip()
			if not self.opts.keep_ip:
				line = self.hide_ip( line )
			if not self.opts.keep_dns:
				line = self.hide_dns( line )
			if not self.opts.keep_ports:
				line = self.hide_ports( line )
			print line
			pass
		if self.opts.want_decoder_ring:
			if not self.opts.keep_ip:
				self.dump_decoder( self.ip_dict, 'IP Decoder' )
			if not self.opts.keep_dns:
				self.dump_decoder( self.dns_dict, 'DNS Decoder' )
			if not self.opts.keep_ports:
				self.dump_decoder( self.port_dict, 'PORT Decoder')
		return

	def	dump_decoder( self, ring, title ):
		print
		print
		banner = 'Decoder Ring: {0}'.format( title )
		print banner
		print '=' * len( banner )
		print
		for key in sorted( ring, key = lambda d: ring[d] ):
			print '{0}\t{1}'.format(
				ring[ key ],
				key,
			)
			pass
		return

	def	_init_dns_hiding( self ):
		self.dns_dict = dict()
		self.dns_dict_count = 0
		self.dns_pattern = r'[0-9a-zA-Z]+[.][0-9a-zA-Z.]+'
		return

	def	_hide_dns( self, mo ):
		host = mo.group( 0 )
		# print 'host={0}'.format( host )
		if host not in self.dns_dict:
			self.dns_dict_count += 1
			replacement = '<HOST{0}>'.format(
				self.dns_dict_count
			)
			self.dns_dict[ host ] = replacement
		return self.dns_dict[ host ]

	def	hide_dns( self, line ):
		# print 'hide_dns={0}'.format( line )
		hidden_line = re.sub(
			self.dns_pattern,
			self._hide_dns,
			line
		)
		return hidden_line

	def	_init_port_hiding( self ):
		self.port_dict       = dict()
		self.port_dict_count = 0
		self.port_pattern    = r':[0-9]+'
		return

	def	_hide_port( self, mo ):
		port = mo.group( 0 )
		if port not in self.port_dict:
			self.port_dict_count += 1
			replacement = ':<PORT{0}>'.format( self.port_dict_count )
			self.port_dict[ port ] = replacement
		return self.port_dict[ port ]

	def	hide_ports( self, line ):
		hidden_line = re.sub(
			self.port_pattern,
			self._hide_port,
			line
		)
		return hidden_line

	def	_init_ip_hiding( self ):
		self.ip_dict       = dict()
		self.ip_dict_count = 0
		self.ip_pattern = r'[0-9]{1,3}[.][0-9]{1,3}[.][0-9]{1,3}'
		return

	def	_hide_ip( self, mo ):
		ip = mo.group( 0 )
		if ip not in self.ip_dict:
			self.ip_dict_count += 1
			replacement = '<IP{0}>'.format( self.ip_dict_count )
			self.ip_dict[ ip ] = replacement
			# print 'self.ip_dict={0}'.format( self.ip_dict )
		return self.ip_dict[ ip ]

	def	hide_ip( self, line ):
		hidden_line = re.sub(
			self.ip_pattern,
			self._hide_ip,
			line
		)
		return hidden_line

if __name__ == '__main__':
	exit( KmRedact().main() )
