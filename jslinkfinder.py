"""
The code below is taken from LinkFinder gitHub repository: 
https://github.com/GerbenJavado/LinkFinder

This code is a Python script that defines a function called `myLinkFinder`
which takes in a string of content and uses a regular expression to find 
and extract links from that content. The function reads the content from
a file called 'www.criteo.com.html', applies the regular expression to find 
links, and then filters those links to only include ones that end with '.js'. 
The filtered links are printed out and returned as a list.
The regular expression used in the function is designed to match various types 
of links, including absolute URLs, relative URLs, and file paths. The function 
also includesa mechanism to remove duplicate links from the results. The script 
is intended to be run as a standalone program, and when executed, it will call 
the `myLinkFinder` function with the specified HTML file as input.
"""
import re
def myLinkFinder(content):
  regex_str = r"""

    (?:"|')                               

    (
      ((?:[a-zA-Z]{1,10}://|//)           
      [^"'/]{1,}\.                        
      [a-zA-Z]{2,}[^"']{0,})              

      |

      ((?:/|\.\./|\./)                    
      [^"'><,;| *()(%%$^/\\\[\]]          
      [^"'><,;|()]{1,})                   

      |

      ([a-zA-Z0-9_\-/]{1,}/               
      [a-zA-Z0-9_\-/.]{1,}                
      \.(?:[a-zA-Z]{1,4}|action)          
      (?:[\?|#][^"|']{0,}|))             

      |

      ([a-zA-Z0-9_\-/]{1,}/               
      [a-zA-Z0-9_\-/]{3,}                 
      (?:[\?|#][^"|']{0,}|))             

      |

      ([a-zA-Z0-9_\-]{1,}                 
      \.(?:php|asp|aspx|jsp|json|
           action|html|js|txt|xml)        
      (?:[\?|#][^"|']{0,}|))              

    )

    (?:"|')                               

  """
  print(regex_str)

  #with open('www.criteo.com.html') as f:
  
  #content = f.read()
  #JS_PATTERN = re.compile(r'<script[^>]+src=["\']([^"\']+)["\']', re.IGNORECASE)
  #JS_PATTERN = re.compile(regex_str)
  # all_matches = [(m.group(1), m.start(0), m.end(0)); for m in re.finditer(regex_str, content)]
  regex = re.compile(regex_str, re.VERBOSE)
  items = [{"link": m.group(1)} for m in re.finditer(regex, content)]
  no_dup = True
  if no_dup:
    # Remove duplication
    all_links = set()
    no_dup_items = []
    for item in items:
        if item["link"] not in all_links:
            all_links.add(item["link"])
            no_dup_items.append(item)
    items = no_dup_items
    #urls = JS_PATTERN.findall(content)
  # Match Regex
  filtered_items = []
  more_regex = r"(?i)\.js$"
  for item in items:
      # Remove other capture groups from regex results
      if more_regex:
          if re.search(more_regex, item["link"]):
              filtered_items.append(item)
    
  print(filtered_items)
  jslist = [item["link"] for item in filtered_items]
  print(jslist)
  #print(urls)
  return jslist

if __name__ == "__main__":
    with open('www.criteo.com.html') as f:
        content = f.read()
        myLinkFinder(content)