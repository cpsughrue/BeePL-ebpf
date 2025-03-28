{
open Lexing
open Parser

let debug = ref true

let print_token str = 
  if !debug then print_endline str
}


let white = [' ' '\t']+
let newline = '\r' | '\n' | "\r\n"
let string = [^ 'L' '(' ')' '.' '#' ' ' '\t' '\n' '\t']+

rule read =
  parse
    | white { read lexbuf }
    | "L" { print_token "LAMBDA"; LAMBDA }
    | "." { print_token "DOT"; DOT }
    | "(" { print_token "LPAREN"; LPAREN }
    | ")" { print_token "RPAREN"; RPAREN }
    | "#" { print_token "COMMENT"; skip_line lexbuf }
    | string { let id = lexeme lexbuf in
           if !debug then Printf.printf "ID(%s)\n" id;
           ID id }
    | newline { print_token "END"; END }
    | eof { print_token "EOF"; EOF }
and skip_line =
  parse
    | newline { new_line lexbuf; read lexbuf }
    | eof { print_token "EOF"; EOF }
    | _ { skip_line lexbuf }
